using System.Net;

using Xunit;

namespace Telegram.OpenIdConnect.AspNetCore.Tests;

/// <summary>
/// A gate that throws (dead database, broken store) must fail CLOSED: no cookie, an error redirect
/// instead of a 500, and a Failure audit row. The exception travels from OnTokenValidated through
/// the OIDC handler's catch into the remote-failure event, which this library handles with a
/// redirect — this test pins that contract so a dead gate dependency can neither take the app down
/// nor let anyone in.
/// </summary>
public sealed class GateFailureTests
{
    private sealed class ThrowingGate : ITelegramSignInGate
    {
        public ValueTask<TelegramSignInDecision> DecideAsync(long telegramUserId, CancellationToken ct) =>
            throw new InvalidOperationException("gate store is down");
    }

    [Fact]
    public async Task ThrowingGate_FailsClosed_WithErrorRedirect_AndFailureAuditRow()
    {
        FakeAuditSink sink = new();
        using TelegramOidcTestHost host = new(new ThrowingGate(), sink);

        using HttpResponseMessage response = await host.SignInAsync("335615025");

        Assert.False(response.Headers.Contains("Set-Cookie") &&
            response.Headers.GetValues("Set-Cookie").Any(c => c.Contains("TelegramCookie", StringComparison.Ordinal)));
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Contains("error=1", response.Headers.Location!.ToString(), StringComparison.Ordinal);

        // The row comes from the remote-failure handler: the gate threw before any audit call on the
        // token-validated path, so exactly one Failure row with no identified user. The Detail carries
        // whatever exception message surfaced through the OIDC handler — not pinned here, wrapping is
        // the framework's business.
        TelegramSignInAuditEvent e = Assert.Single(sink.Events);
        Assert.Equal(TelegramSignInOutcome.Failure, e.Outcome);
        Assert.Null(e.TelegramUserId);
    }
}
