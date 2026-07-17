using Microsoft.AspNetCore.Http;

namespace Telegram.OpenIdConnect.AspNetCore;

/// <summary>Configuration for <see cref="TelegramOidcExtensions.AddTelegramOidc"/>.</summary>
public sealed class TelegramOidcOptions
{
    /// <summary>Telegram Bot ID (= OIDC client_id, = id_token aud). Numeric string.</summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>Telegram Bot token (= OIDC client_secret).</summary>
    public string ClientSecret { get; set; } = string.Empty;

    /// <summary>OIDC discovery document address.</summary>
    public string MetadataAddress { get; set; } = "https://oauth.telegram.org/.well-known/openid-configuration";

    /// <summary>Path the OIDC handler intercepts to process the authorization code callback.</summary>
    public string CallbackPath { get; set; } = "/signin-telegram";

    /// <summary>Path the cookie handler redirects to when authentication is required.</summary>
    public string LoginPath { get; set; } = "/login";

    /// <summary>
    /// Where a denied sign-in is redirected (issued by the sign-in flow; also used as the cookie
    /// scheme's <c>AccessDeniedPath</c> for authorization denials).
    /// </summary>
    public string AccessDeniedPath { get; set; } = "/login?denied=1";

    /// <summary>Name of the cookie authentication scheme registered by this library.</summary>
    public string CookieScheme { get; set; } = "TelegramCookie";

    /// <summary>Name of the OpenID Connect authentication scheme registered by this library.</summary>
    public string OidcScheme { get; set; } = "TelegramOidc";

    /// <summary>Sliding expiration window, in hours, for the sign-in cookie.</summary>
    public int CookieTtlHours { get; set; } = 12;

    /// <summary>Default landing after sign-in when the challenge carries no (safe) returnUrl.</summary>
    public string DefaultReturnUrl { get; set; } = "/";

    /// <summary>
    /// Resolves the client IP recorded in the audit trail. Default (<c>null</c>):
    /// <see cref="Microsoft.AspNetCore.Http.ConnectionInfo.RemoteIpAddress"/> — the framework's own
    /// notion of the caller, which reflects whatever forwarded-headers middleware the host has
    /// configured (none configured -> the socket peer).
    /// <para>
    /// Supply a resolver to read a forwarded header instead — but ONLY when a reverse proxy in front
    /// of this app OVERWRITES that header unconditionally. Without such a proxy the header is
    /// attacker-controlled: any client could stamp an arbitrary IP into your audit trail.
    /// </para>
    /// <para>
    /// Whatever the resolver returns is normalized from IPv4-mapped IPv6 form
    /// (<c>::ffff:1.2.3.4</c> -> <c>1.2.3.4</c>) by the library, so hosts need not handle that.
    /// </para>
    /// </summary>
    public Func<HttpContext, string?>? ClientIpResolver { get; set; }
}
