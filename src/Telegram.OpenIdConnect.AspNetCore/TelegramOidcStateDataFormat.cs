using System.Security.Cryptography;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;

namespace Telegram.OpenIdConnect.AspNetCore;

/// <summary>
/// Keeps the OIDC <c>state</c> query parameter short by storing the real DataProtection-protected
/// <see cref="AuthenticationProperties"/> payload in a short-lived server-set cookie and emitting only
/// a ~22-char random id as the wire value.
/// <para>
/// Telegram's authorization endpoint (<c>https://oauth.telegram.org/auth</c>) hard-rejects any
/// <c>state</c> longer than 256 characters with the plain-text response <c>state too long</c>. ASP.NET
/// Core's default <see cref="PropertiesDataFormat"/> emits the protected payload inline, which for this
/// host is ~500 chars — architecturally over Telegram's limit, so admin login was broken end-to-end.
/// The id-plus-cookie indirection keeps the protected payload intact (it is still DataProtection-signed
/// and still validated on the callback) while putting a fixed, tiny value on the wire.
/// </para>
/// </summary>
internal sealed class TelegramOidcStateDataFormat : ISecureDataFormat<AuthenticationProperties>
{
    /// <summary>Prefix for the per-flow state cookie; the random id is appended verbatim.</summary>
    private const string CookiePrefix = ".TelegramOidcState.";

    /// <summary>
    /// Upper bound on an acceptable state id. A real id is ~22 chars (16 random bytes, base64url);
    /// anything longer is not ours and is rejected before it can reach cookie-name handling.
    /// </summary>
    private const int MaxIdLength = 64;

    /// <summary>Generous enough for a human to complete the Telegram consent screen, short enough to bound replay.</summary>
    private static readonly TimeSpan StateLifetime = TimeSpan.FromMinutes(15);

    private readonly ISecureDataFormat<AuthenticationProperties> _inner;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public TelegramOidcStateDataFormat(
        ISecureDataFormat<AuthenticationProperties> inner,
        IHttpContextAccessor httpContextAccessor)
    {
        _inner = inner;
        _httpContextAccessor = httpContextAccessor;
    }

    public string Protect(AuthenticationProperties data) => Protect(data, purpose: null);

    public string Protect(AuthenticationProperties data, string? purpose)
    {
        string payload = _inner.Protect(data, purpose);
        string id = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(16));

        HttpContext? http = _httpContextAccessor.HttpContext;
        if (http is null)
        {
            // No request in flight — nowhere to stash the payload, so fall back to the inline format
            // rather than emitting an id that could never be resolved.
            return payload;
        }

        http.Response.Cookies.Append(CookiePrefix + id, payload, BuildCookieOptions(withExpiry: true));
        return id;
    }

    public AuthenticationProperties? Unprotect(string? protectedText) => Unprotect(protectedText, purpose: null);

    public AuthenticationProperties? Unprotect(string? protectedText, string? purpose)
    {
        // protectedText is attacker-supplied (it arrives straight off the callback query string).
        // Validate it as a base64url id BEFORE it is ever concatenated into a cookie name, so a
        // crafted state cannot inject cookie-name/header separators.
        if (!IsValidStateId(protectedText))
        {
            return null;
        }

        HttpContext? http = _httpContextAccessor.HttpContext;
        if (http is null)
        {
            return null;
        }

        string cookieName = CookiePrefix + protectedText;
        if (!http.Request.Cookies.TryGetValue(cookieName, out string? payload) || string.IsNullOrEmpty(payload))
        {
            // Missing cookie means expired or already-consumed state — fail closed.
            return null;
        }

        // Single-use: drop the cookie as soon as it is read, so a replayed state finds nothing.
        http.Response.Cookies.Delete(cookieName, BuildCookieOptions(withExpiry: false));

        return _inner.Unprotect(payload, purpose);
    }

    private static bool IsValidStateId(string? value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > MaxIdLength)
        {
            return false;
        }

        foreach (char c in value)
        {
            bool isBase64Url = (c >= 'A' && c <= 'Z')
                || (c >= 'a' && c <= 'z')
                || (c >= '0' && c <= '9')
                || c == '-'
                || c == '_';

            if (!isBase64Url)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Delete must mirror the append options exactly (Path/Secure/HttpOnly/SameSite) or the browser
    /// keeps the original cookie alongside the expired one.
    /// </summary>
    private static CookieOptions BuildCookieOptions(bool withExpiry)
    {
        CookieOptions cookieOptions = new()
        {
            HttpOnly = true,
            Secure = true,
            // Lax works because ResponseMode=Query makes the callback a top-level GET redirect.
            SameSite = SameSiteMode.Lax,
            IsEssential = true,
            Path = "/",
        };

        if (withExpiry)
        {
            cookieOptions.Expires = DateTimeOffset.UtcNow.Add(StateLifetime);
        }

        return cookieOptions;
    }
}
