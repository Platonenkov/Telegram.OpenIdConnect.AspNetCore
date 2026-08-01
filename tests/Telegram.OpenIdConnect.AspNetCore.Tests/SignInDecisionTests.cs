using System.Security.Claims;

using Xunit;

namespace Telegram.OpenIdConnect.AspNetCore.Tests;

/// <summary>
/// The gate decides whether the user may sign in AND with which claims. The library attaches what it
/// is handed and knows nothing about roles or permissions — that keeps non-admin use cases possible
/// without touching the library.
/// </summary>
public sealed class SignInDecisionTests
{
    private const long AllowedId = 1000000001L;

    private sealed class ClaimsGate : ITelegramSignInGate
    {
        public ValueTask<TelegramSignInDecision> DecideAsync(long telegramUserId, CancellationToken ct) =>
            ValueTask.FromResult(telegramUserId == AllowedId
                ? new TelegramSignInDecision(true, [new Claim(ClaimTypes.Role, "Admin"), new Claim("tier", "gold")])
                : new TelegramSignInDecision(false));
    }

    [Fact]
    public async Task ClaimsFromGate_ReachTheSignedInPrincipal()
    {
        using TelegramOidcTestHost host = new(new ClaimsGate());

        ClaimsPrincipal principal = await host.SignInAndReadPrincipalAsync(AllowedId.ToString());

        Assert.True(principal.IsInRole("Admin"));
        Assert.Equal("gold", principal.FindFirst("tier")?.Value);
    }

    /// <summary>The library always adds its own telegram_user_id claim, on top of the gate's.</summary>
    [Fact]
    public async Task TelegramUserIdClaim_IsAlwaysAdded()
    {
        using TelegramOidcTestHost host = new(new ClaimsGate());

        ClaimsPrincipal principal = await host.SignInAndReadPrincipalAsync(AllowedId.ToString());

        Assert.Equal(AllowedId.ToString(), principal.FindFirst("telegram_user_id")?.Value);
    }

    /// <summary>A decision with no claims is valid: the host may want a plain authenticated user.</summary>
    [Fact]
    public async Task DecisionWithoutClaims_StillSignsIn()
    {
        using TelegramOidcTestHost host = new(new FakeSignInGate(AllowedId));

        ClaimsPrincipal principal = await host.SignInAndReadPrincipalAsync(AllowedId.ToString());

        Assert.True(principal.Identity!.IsAuthenticated);
        Assert.Equal(AllowedId.ToString(), principal.FindFirst("telegram_user_id")?.Value);
    }
}
