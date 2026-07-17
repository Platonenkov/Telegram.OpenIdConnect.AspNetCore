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
    public string LoginPath { get; set; } = "/admin/login";

    /// <summary>Path the cookie handler redirects to when the sign-in gate denies access.</summary>
    public string AccessDeniedPath { get; set; } = "/admin/login?denied=1";

    /// <summary>Name of the cookie authentication scheme registered by this library.</summary>
    public string CookieScheme { get; set; } = "TelegramAdminCookie";

    /// <summary>Name of the OpenID Connect authentication scheme registered by this library.</summary>
    public string OidcScheme { get; set; } = "TelegramOidc";

    /// <summary>Name of the authorization policy registered by this library.</summary>
    public string PolicyName { get; set; } = "TelegramAdmin";

    /// <summary>Role claim value granted to a successfully signed-in Telegram user.</summary>
    public string RoleName { get; set; } = "TelegramAdmin";

    /// <summary>Sliding expiration window, in hours, for the sign-in cookie.</summary>
    public int CookieTtlHours { get; set; } = 12;

    /// <summary>Default landing after sign-in when the challenge carries no (safe) returnUrl.</summary>
    public string DefaultReturnUrl { get; set; } = "/";
}
