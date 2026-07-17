using Telegram.OpenIdConnect.AspNetCore;

namespace Telegram.OpenIdConnect.AspNetCore.Tests;

public sealed class SafeLocalReturnUrlTests
{
    [Theory]
    [InlineData("/admin/installs", "/admin/installs")]
    [InlineData("/admin/login-audit?page=2", "/admin/login-audit?page=2")]
    [InlineData(null, "/fallback")]
    [InlineData("", "/fallback")]
    [InlineData("https://evil.com", "/fallback")]
    [InlineData("//evil.com", "/fallback")]
    [InlineData("/\\evil.com", "/fallback")]
    [InlineData("http://x", "/fallback")]
    [InlineData("javascript:alert(1)", "/fallback")]
    public void SafeLocalReturnUrl_RejectsNonLocal(string? input, string expected)
    {
        Assert.Equal(expected, TelegramOidcEndpoints.SafeLocalReturnUrl(input, "/fallback"));
    }
}
