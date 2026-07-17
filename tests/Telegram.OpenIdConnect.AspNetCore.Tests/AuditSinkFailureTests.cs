using System.Security.Claims;
using Xunit;

namespace Telegram.OpenIdConnect.AspNetCore.Tests;

/// <summary>
/// The audit write is best-effort: a broken sink (bad connection string, dead database) must never
/// lock admins out. The library wraps the call — this proves it, because nothing else does.
/// </summary>
public sealed class AuditSinkFailureTests
{
    private const long AllowedId = 335615025L;

    private sealed class ThrowingSink : ITelegramSignInAuditSink
    {
        public ValueTask RecordAsync(TelegramSignInAuditEvent e, CancellationToken ct) =>
            throw new InvalidOperationException("sink is down");
    }

    [Fact]
    public async Task ThrowingSink_DoesNotBreakSignIn()
    {
        using TelegramOidcTestHost host = new(new FakeSignInGate(AllowedId), new ThrowingSink());

        ClaimsPrincipal principal = await host.SignInAndReadPrincipalAsync(AllowedId.ToString());

        Assert.True(principal.Identity!.IsAuthenticated);
        Assert.Equal(AllowedId.ToString(), principal.FindFirst("telegram_user_id")?.Value);
    }
}
