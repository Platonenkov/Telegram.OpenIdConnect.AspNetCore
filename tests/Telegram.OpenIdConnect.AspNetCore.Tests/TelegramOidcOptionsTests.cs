using Xunit;

namespace Telegram.OpenIdConnect.AspNetCore.Tests;

/// <summary>
/// Defaults are public contract: changing any of these silently breaks hosts that rely on them.
/// DefaultReturnUrl is "/" and NOT a host-specific page — this package ships to strangers.
/// </summary>
public sealed class TelegramOidcOptionsTests
{
    [Fact]
    public void Defaults_AreTheDocumentedContract()
    {
        TelegramOidcOptions o = new();

        Assert.Equal(string.Empty, o.ClientId);
        Assert.Equal(string.Empty, o.ClientSecret);
        Assert.Equal("https://oauth.telegram.org/.well-known/openid-configuration", o.MetadataAddress);
        Assert.Equal("/signin-telegram", o.CallbackPath);
        Assert.Equal("/login", o.LoginPath);
        Assert.Equal("/login?denied=1", o.AccessDeniedPath);
        Assert.Equal("TelegramCookie", o.CookieScheme);
        Assert.Equal("TelegramOidc", o.OidcScheme);
        Assert.Equal(12, o.CookieTtlHours);
        Assert.Equal("/", o.DefaultReturnUrl);
        Assert.Null(o.ClientIpResolver);
        Assert.False(o.LogPersonalData);
    }
}
