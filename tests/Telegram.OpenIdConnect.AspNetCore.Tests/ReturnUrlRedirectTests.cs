using System.Net;

namespace Telegram.OpenIdConnect.AspNetCore.Tests;

/// <summary>
/// End-to-end check of the open-redirect fix: the hostile returnUrl goes through the real challenge
/// endpoint, the OIDC round trip and the success redirect, and the final Location must be the
/// configured default, never the attacker's value.
/// </summary>
public sealed class ReturnUrlRedirectTests
{
    private const long AllowedId = 1000000001L;
    private const string DefaultReturnUrl = "/home";

    [Theory]
    [InlineData("/%09/evil.test")]
    [InlineData("/%0a/evil.test")]
    [InlineData("/%0d/evil.test")]
    [InlineData("/%2509/evil.test")]
    [InlineData("/%5Cevil.test")]
    [InlineData("%2F%2Fevil.test")]
    [InlineData("https%3A%2F%2Fevil.test")]
    public async Task HostileReturnUrl_LandsOnDefaultReturnUrl(string encodedReturnUrl)
    {
        using TelegramOidcTestHost host = new(
            new FakeSignInGate(AllowedId),
            configure: o => o.DefaultReturnUrl = DefaultReturnUrl);

        using HttpResponseMessage response = await host.SignInAsync(
            AllowedId.ToString(), encodedReturnUrl: encodedReturnUrl);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal(DefaultReturnUrl, response.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task LocalReturnUrl_IsHonoured()
    {
        using TelegramOidcTestHost host = new(
            new FakeSignInGate(AllowedId),
            configure: o => o.DefaultReturnUrl = DefaultReturnUrl);

        using HttpResponseMessage response = await host.SignInAsync(
            AllowedId.ToString(), encodedReturnUrl: "%2Fdashboard%3Fpage%3D2");

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/dashboard?page=2", response.Headers.Location!.OriginalString);
    }
}
