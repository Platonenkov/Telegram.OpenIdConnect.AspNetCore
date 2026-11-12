using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Telegram.OpenIdConnect.AspNetCore;

/// <summary>Maps the HTTP endpoints Telegram OpenID Connect sign-in needs.</summary>
public static class TelegramOidcEndpoints
{
    /// <summary>
    /// Maps the challenge (GET {CallbackPath}/challenge) and logout (POST {CallbackPath}/logout)
    /// endpoints. Challenge kicks off the OIDC redirect; logout is a local cookie sign-out with
    /// manual antiforgery validation.
    /// </summary>
    public static IEndpointRouteBuilder MapTelegramOidcEndpoints(this IEndpointRouteBuilder endpoints)
    {
        TelegramOidcOptions options = endpoints.ServiceProvider.GetRequiredService<TelegramOidcOptions>();
        string basePath = options.CallbackPath.TrimEnd('/');

        if (string.IsNullOrWhiteSpace(options.ClientId))
        {
            ILogger startupLogger = endpoints.ServiceProvider.GetRequiredService<ILoggerFactory>().CreateLogger("TelegramOidc");
            startupLogger.LogWarning(
                "Telegram OIDC is not configured; sign-in will be unreachable until TelegramOidc:ClientId/ClientSecret are set.");
        }

        endpoints.MapGet(basePath + "/challenge", (HttpContext http, IOptionsMonitor<OpenIdConnectOptions> oidcMonitor, string? returnUrl) =>
        {
            OpenIdConnectOptions oidcOptions = oidcMonitor.Get(options.OidcScheme);
            bool clientIdMissing = string.IsNullOrWhiteSpace(oidcOptions.ClientId) ||
                string.Equals(oidcOptions.ClientId, TelegramOidcExtensions.UnconfiguredClientId, StringComparison.Ordinal);
            bool clientSecretMissing = string.IsNullOrWhiteSpace(oidcOptions.ClientSecret) ||
                string.Equals(oidcOptions.ClientSecret, TelegramOidcExtensions.UnconfiguredClientSecret, StringComparison.Ordinal);
            if (clientIdMissing || clientSecretMissing)
            {
                ILogger logger = http.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("TelegramOidc");
                logger.LogWarning(
                    "Telegram OIDC sign-in attempted but not configured (ClientId missing: {ClientIdMissing}, ClientSecret missing: {ClientSecretMissing}).",
                    clientIdMissing, clientSecretMissing);
                return Results.Text("Telegram OIDC sign-in is not configured.", statusCode: StatusCodes.Status503ServiceUnavailable);
            }

            string target = SafeLocalReturnUrl(returnUrl, options.DefaultReturnUrl);
            return Results.Challenge(new AuthenticationProperties { RedirectUri = target }, [options.OidcScheme]);
        });

        endpoints.MapPost(basePath + "/logout", async (HttpContext http, IAntiforgery antiforgery) =>
        {
            try
            {
                await antiforgery.ValidateRequestAsync(http).ConfigureAwait(false);
            }
            catch (AntiforgeryValidationException)
            {
                return Results.BadRequest("Invalid antiforgery token.");
            }

            await http.SignOutAsync(options.CookieScheme).ConfigureAwait(false);
            return Results.Redirect(options.LoginPath);
        });

        return endpoints;
    }

    // Enough for any legitimately encoded path; a value still changing after this many rounds is
    // layered encoding, which only an attacker produces, so it is refused rather than decoded further.
    private const int MaxDecodeRounds = 3;

    /// <summary>
    /// Returns <paramref name="returnUrl"/> unchanged only if it is a plain local path; otherwise
    /// <paramref name="fallback"/>. A plain local path starts with a single <c>/</c>, has no <c>//</c>
    /// in its path part, and contains no <c>\</c> and no control character (C0, DEL, C1). The same
    /// rules are applied to every percent-decoded form of the value, so encoded and double-encoded
    /// variants are refused too.
    /// </summary>
    internal static string SafeLocalReturnUrl(string? returnUrl, string fallback)
    {
        if (string.IsNullOrEmpty(returnUrl))
        {
            return fallback;
        }

        string current = returnUrl;
        for (int round = 0; round <= MaxDecodeRounds; round++)
        {
            if (!IsPlainLocalPath(current))
            {
                return fallback;
            }

            string decoded = Uri.UnescapeDataString(current);
            if (string.Equals(decoded, current, StringComparison.Ordinal))
            {
                return returnUrl;
            }

            current = decoded;
        }

        return fallback;
    }

    /// <remarks>
    /// Browsers strip tab, LF and CR anywhere in a URL and treat '\' as '/', so "/\t/evil.test" or
    /// "/\evil.test" in a Location header becomes the protocol-relative "//evil.test". Checking only
    /// the first two characters, as earlier versions did, misses both. A value that starts with '/'
    /// cannot carry a scheme, so no separate scheme check is needed.
    /// </remarks>
    private static bool IsPlainLocalPath(string value)
    {
        if (value.Length == 0 || value[0] != '/')
        {
            return false;
        }

        int pathEnd = value.Length;
        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];

            // char.IsControl covers exactly C0 (U+0000-U+001F), DEL (U+007F) and C1 (U+0080-U+009F).
            if (char.IsControl(c) || c == '\\')
            {
                return false;
            }

            if (pathEnd == value.Length && (c == '?' || c == '#'))
            {
                pathEnd = i;
            }
        }

        return value.AsSpan(0, pathEnd).IndexOf("//", StringComparison.Ordinal) < 0;
    }
}
