using System.Net;
using System.Security.Claims;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Telegram.OpenIdConnect.AspNetCore;

/// <summary>Registers Telegram OpenID Connect sign-in.</summary>
public static class TelegramOidcExtensions
{
    /// <summary>
    /// Placeholder client id used when the host leaves <see cref="TelegramOidcOptions.ClientId"/>
    /// empty. It lets <c>OpenIdConnectOptions.Validate()</c> (which runs on EVERY request, because the
    /// OIDC scheme is an <see cref="Microsoft.AspNetCore.Authentication.IAuthenticationRequestHandler"/>)
    /// pass instead of throwing, so core auth stays healthy; the challenge endpoint gates on this value
    /// and returns 503 while it is in place.
    /// </summary>
    internal const string UnconfiguredClientId = "__telegram_oidc_unconfigured__";

    /// <summary>
    /// Placeholder client secret used when the host leaves <see cref="TelegramOidcOptions.ClientSecret"/>
    /// empty. Mirrors <see cref="UnconfiguredClientId"/> so <c>OpenIdConnectOptions.Validate()</c> keeps
    /// passing; the challenge endpoint also gates on this value and returns 503 while it is in place.
    /// </summary>
    internal const string UnconfiguredClientSecret = "__unconfigured__";

    /// <summary>
    /// Wires cookie + Telegram OpenID Connect (authorization code + PKCE) sign-in. The host must also
    /// register an <see cref="ITelegramSignInGate"/>; an <see cref="ITelegramSignInAuditSink"/> is
    /// optional. Reuse your existing scheme names via <paramref name="configure"/> so existing
    /// [Authorize] usages stay valid.
    /// </summary>
    public static IServiceCollection AddTelegramOidc(this IServiceCollection services, Action<TelegramOidcOptions> configure)
    {
        TelegramOidcOptions options = new();
        configure(options);
        services.AddSingleton(options);
        services.AddHttpContextAccessor();

        services.AddAuthentication(options.CookieScheme)
            .AddCookie(options.CookieScheme, cookie =>
            {
                cookie.LoginPath = options.LoginPath;
                cookie.AccessDeniedPath = options.AccessDeniedPath;
                cookie.ExpireTimeSpan = TimeSpan.FromHours(options.CookieTtlHours);
                cookie.SlidingExpiration = true;
                cookie.Cookie.HttpOnly = true;
                cookie.Cookie.SameSite = SameSiteMode.Lax;
                cookie.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            })
            .AddOpenIdConnect(options.OidcScheme, oidc =>
            {
                // Telegram's oauth.telegram.org endpoints intermittently answer with
                // "Content-Encoding: gzip" even when the request carried NO Accept-Encoding header
                // (measured 2026-07-16: 4 of 10 unsolicited responses came back gzipped). That is a
                // server-side HTTP violation we cannot fix, and without decompression the raw gzip
                // bytes reach the JSON parser: discovery/JWKS then blow up with IDX20803/IDX10805 and
                // every challenge 500s — randomly, only on the nodes that gzip. Decompress whatever
                // they send, solicited or not, so the flow is deterministic.
                oidc.BackchannelHttpHandler = new HttpClientHandler
                {
                    AutomaticDecompression = DecompressionMethods.All,
                };
                oidc.MetadataAddress = options.MetadataAddress;
                // Placeholder-on-empty so OpenIdConnectOptions.Validate() always passes and the core
                // auth service stays healthy even when admin OIDC is unconfigured. The challenge
                // endpoint gates on the effective ClientId and returns 503 while the placeholder is set.
                oidc.ClientId = string.IsNullOrWhiteSpace(options.ClientId) ? UnconfiguredClientId : options.ClientId;
                oidc.ClientSecret = string.IsNullOrWhiteSpace(options.ClientSecret) ? UnconfiguredClientSecret : options.ClientSecret;
                oidc.ResponseType = "code";
                // ASP.NET defaults to form_post, which Telegram's discovery does not advertise
                // (response_modes_supported is absent) and which would force a cross-site POST
                // callback, requiring SameSite=None cookies. query is the OAuth2 default for the
                // code flow and keeps the callback a top-level GET redirect, so SameSite=Lax works.
                oidc.ResponseMode = OpenIdConnectResponseMode.Query;
                oidc.UsePkce = true;
                oidc.CallbackPath = options.CallbackPath;
                oidc.SignInScheme = options.CookieScheme;
                oidc.SaveTokens = false;
                oidc.GetClaimsFromUserInfoEndpoint = false;
                oidc.MapInboundClaims = false; // keep raw claim types: sub, name, preferred_username, picture
                oidc.Scope.Clear();
                oidc.Scope.Add("openid");
                oidc.Scope.Add("profile");
                oidc.TokenValidationParameters.NameClaimType = "preferred_username";
                // aud is validated against ClientId and iss against discovery issuer by default.
                // nonce validation stays ON (default) — do not disable.
                oidc.Events = new OpenIdConnectEvents
                {
                    OnTokenValidated = ctx => OnTokenValidatedAsync(ctx, options),
                    OnAccessDenied = ctx => OnAccessDeniedAsync(ctx, options),
                    OnRemoteFailure = ctx => OnRemoteFailureAsync(ctx, options),
                };
            });

        // Replace the default inline PropertiesDataFormat with the cookie-backed short-id format, so
        // the emitted state stays ~22 chars instead of ~500 — Telegram rejects state > 256 chars with
        // "state too long". Done as a DI-aware Configure (not inside the AddOpenIdConnect lambda,
        // which has no service access) so the DataProtection provider can be resolved for the
        // protector; the purpose chain mirrors what OpenIdConnectHandler builds for itself.
        services.AddOptions<OpenIdConnectOptions>(options.OidcScheme)
            .Configure<IDataProtectionProvider, IHttpContextAccessor>((oidc, dataProtectionProvider, httpContextAccessor) =>
            {
                IDataProtector protector = dataProtectionProvider.CreateProtector(
                    typeof(OpenIdConnectHandler).FullName!, options.OidcScheme, "v1");
                ISecureDataFormat<AuthenticationProperties> inner = new PropertiesDataFormat(protector);
                oidc.StateDataFormat = new TelegramOidcStateDataFormat(inner, httpContextAccessor);
            });

        return services;
    }

    private static async Task OnTokenValidatedAsync(
        Microsoft.AspNetCore.Authentication.OpenIdConnect.TokenValidatedContext ctx,
        TelegramOidcOptions options)
    {
        HttpContext http = ctx.HttpContext;
        ILogger logger = http.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("TelegramOidc");

        // Telegram's OIDC "sub" is its own OpenID subject identifier and is NOT the Bot-API user id —
        // it does not match the allow-list (which is keyed on Bot-API ids, the same ids the legacy
        // Login Widget delivered). The Bot-API id arrives in the separate "id" claim; that is what the
        // allow-list, the audit trail, and the "telegram_user_id" cookie claim must use. Never fall
        // back to "sub" here — that would silently authorize against the wrong identifier namespace.
        string? id = ctx.Principal?.FindFirst("id")?.Value;
        string? username = ctx.Principal?.FindFirst("preferred_username")?.Value;
        string? displayName = ctx.Principal?.FindFirst("name")?.Value;
        string? pictureUrl = ctx.Principal?.FindFirst("picture")?.Value;
        string? clientIp = ResolveClientIp(http, options);

        if (!long.TryParse(id, out long telegramUserId))
        {
            logger.LogWarning("Telegram OIDC token missing/invalid id claim.");
            await RecordAsync(http, new TelegramSignInAuditEvent(
                TelegramSignInOutcome.Failure, null, username, displayName, pictureUrl, clientIp, "missing id claim")).ConfigureAwait(false);
            ctx.Response.Redirect(options.LoginPath + "?error=1");
            ctx.HandleResponse();
            return;
        }

        ITelegramSignInGate gate = http.RequestServices.GetRequiredService<ITelegramSignInGate>();
        TelegramSignInDecision decision = await gate.DecideAsync(telegramUserId, http.RequestAborted).ConfigureAwait(false);

        if (!decision.Allowed)
        {
            logger.LogWarning("Denied sign-in for Telegram id {TelegramUserId} (@{Username}) from {ClientIp}.",
                telegramUserId, username, clientIp);
            await RecordAsync(http, new TelegramSignInAuditEvent(
                TelegramSignInOutcome.Denied, telegramUserId, username, displayName, pictureUrl, clientIp, "rejected by gate")).ConfigureAwait(false);
            ctx.Response.Redirect(options.AccessDeniedPath);
            ctx.HandleResponse();
            return;
        }

        ClaimsIdentity identity = (ClaimsIdentity)ctx.Principal!.Identity!;

        if (decision.Claims is not null)
        {
            foreach (Claim claim in decision.Claims)
            {
                identity.AddClaim(claim);
            }
        }

        identity.AddClaim(new Claim("telegram_user_id", telegramUserId.ToString()));

        logger.LogInformation("Admin sign-in for Telegram id {TelegramUserId} (@{Username}) from {ClientIp}.",
            telegramUserId, username, clientIp);
        await RecordAsync(http, new TelegramSignInAuditEvent(
            TelegramSignInOutcome.Success, telegramUserId, username, displayName, pictureUrl, clientIp, null)).ConfigureAwait(false);
    }

    private static async Task OnAccessDeniedAsync(
        Microsoft.AspNetCore.Authentication.AccessDeniedContext ctx,
        TelegramOidcOptions options)
    {
        HttpContext http = ctx.HttpContext;
        string? clientIp = ResolveClientIp(http, options);

        await RecordAsync(http, new TelegramSignInAuditEvent(
            TelegramSignInOutcome.Failure, null, null, null, null, clientIp, "access_denied")).ConfigureAwait(false);

        ctx.Response.Redirect(options.LoginPath + "?error=1");
        ctx.HandleResponse();
    }

    private static async Task OnRemoteFailureAsync(
        Microsoft.AspNetCore.Authentication.RemoteFailureContext ctx,
        TelegramOidcOptions options)
    {
        HttpContext http = ctx.HttpContext;
        ILogger logger = http.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("TelegramOidc");
        string? reason = ctx.Failure?.Message;
        string? clientIp = ResolveClientIp(http, options);

        logger.LogWarning(ctx.Failure, "Telegram OIDC remote failure: {Reason}", reason);
        await RecordAsync(http, new TelegramSignInAuditEvent(
            TelegramSignInOutcome.Failure, null, null, null, null, clientIp, reason)).ConfigureAwait(false);

        ctx.HandleResponse();
        ctx.Response.Redirect(options.LoginPath + "?error=1");
    }

    /// <summary>
    /// Resolves the client IP for the audit trail. Uses <see cref="TelegramOidcOptions.ClientIpResolver"/>
    /// when the host supplied one, otherwise the framework's RemoteIpAddress. The result is normalized
    /// from IPv4-mapped IPv6 form either way, so audit rows are consistent regardless of the source.
    /// No request header is trusted by default: without a proxy that overwrites it, a header is
    /// attacker-controlled.
    /// </summary>
    private static string? ResolveClientIp(HttpContext http, TelegramOidcOptions options)
    {
        string? raw = options.ClientIpResolver is not null
            ? options.ClientIpResolver(http)
            : http.Connection.RemoteIpAddress?.ToString();

        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        return NormalizeIp(raw.Trim());
    }

    /// <summary>Collapses an IPv4-mapped IPv6 address (<c>::ffff:a.b.c.d</c>) to plain IPv4.</summary>
    private static string NormalizeIp(string ip)
    {
        if (IPAddress.TryParse(ip, out IPAddress? parsed) && parsed.IsIPv4MappedToIPv6)
        {
            return parsed.MapToIPv4().ToString();
        }

        return ip;
    }

    /// <summary>Audit write is best-effort — a sink failure must never break sign-in.</summary>
    private static async Task RecordAsync(HttpContext http, TelegramSignInAuditEvent e)
    {
        ITelegramSignInAuditSink? sink = http.RequestServices.GetService<ITelegramSignInAuditSink>();
        if (sink is null)
        {
            return;
        }

        try
        {
            await sink.RecordAsync(e, http.RequestAborted).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            ILogger logger = http.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("TelegramOidc");
            logger.LogWarning(ex, "Admin login audit sink failed to record {Outcome}.", e.Outcome);
        }
    }
}
