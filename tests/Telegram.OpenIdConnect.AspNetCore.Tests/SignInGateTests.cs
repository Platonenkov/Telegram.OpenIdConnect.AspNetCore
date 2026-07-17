using System.Net;

using Xunit;

namespace Telegram.OpenIdConnect.AspNetCore.Tests;

/// <summary>
/// Drives the real Telegram OIDC middleware end-to-end without a live Telegram: discovery, signing
/// keys and the code->token backchannel are stubbed in-process, so a self-signed id_token minted
/// with a known key flows through the actual code-exchange + nonce + signature validation and fires
/// the gate.
///
/// Minted tokens always carry BOTH claims, mirroring Telegram's real id_token shape: an opaque
/// `sub` (Telegram's own OIDC subject, unrelated to the Bot API) and an `id` (the Bot-API user id
/// the gate is actually keyed on).
/// </summary>
public sealed class SignInGateTests
{
    private const long AllowedId = 335615025L;
    private const long UnknownId = 999000111L;

    [Fact]
    public async Task AllowedId_GetsCookie_AndSuccessAuditRow()
    {
        FakeAuditSink sink = new();
        using TelegramOidcTestHost host = new(new FakeSignInGate(AllowedId), sink);

        using HttpResponseMessage response = await host.SignInAsync(AllowedId.ToString());

        Assert.Contains(response.Headers.GetValues("Set-Cookie"), c => c.Contains("TelegramCookie", StringComparison.Ordinal));
        TelegramSignInAuditEvent e = Assert.Single(sink.Events);
        Assert.Equal(TelegramSignInOutcome.Success, e.Outcome);
        Assert.Equal(AllowedId, e.TelegramUserId);
    }

    [Fact]
    public async Task UnknownId_IsDenied_NoCookie_DeniedAuditRow_RedirectsToAccessDenied()
    {
        FakeAuditSink sink = new();
        using TelegramOidcTestHost host = new(new FakeSignInGate(AllowedId), sink);

        using HttpResponseMessage response = await host.SignInAsync(UnknownId.ToString());

        Assert.False(response.Headers.Contains("Set-Cookie") &&
            response.Headers.GetValues("Set-Cookie").Any(c => c.Contains("TelegramCookie", StringComparison.Ordinal)));
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Contains("denied=1", response.Headers.Location!.ToString(), StringComparison.Ordinal);
        TelegramSignInAuditEvent e = Assert.Single(sink.Events);
        Assert.Equal(TelegramSignInOutcome.Denied, e.Outcome);
        Assert.Equal(UnknownId, e.TelegramUserId);
    }

    /// <summary>
    /// The gate must key on `id`, never on `sub`. Here `sub` carries an allow-listed value while
    /// `id` does not: a implementation that fell back to `sub` would let this through.
    /// </summary>
    [Fact]
    public async Task SubMatchesAllowlist_ButIdDoesNot_StillDenied()
    {
        FakeAuditSink sink = new();
        using TelegramOidcTestHost host = new(new FakeSignInGate(AllowedId), sink);

        using HttpResponseMessage response = await host.SignInAsync(
            idClaim: UnknownId.ToString(),
            subClaim: AllowedId.ToString());

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Contains("denied=1", response.Headers.Location!.ToString(), StringComparison.Ordinal);
        TelegramSignInAuditEvent e = Assert.Single(sink.Events);
        Assert.Equal(TelegramSignInOutcome.Denied, e.Outcome);
        Assert.Equal(UnknownId, e.TelegramUserId);
    }

    [Fact]
    public async Task NoIdClaim_FailsClosed_WithFailureAuditRow()
    {
        FakeAuditSink sink = new();
        using TelegramOidcTestHost host = new(new FakeSignInGate(AllowedId), sink);

        using HttpResponseMessage response = await host.SignInAsync(idClaim: null);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Contains("error=1", response.Headers.Location!.ToString(), StringComparison.Ordinal);
        TelegramSignInAuditEvent e = Assert.Single(sink.Events);
        Assert.Equal(TelegramSignInOutcome.Failure, e.Outcome);
        Assert.Null(e.TelegramUserId);
        Assert.Equal("missing id claim", e.Detail);
    }
}
