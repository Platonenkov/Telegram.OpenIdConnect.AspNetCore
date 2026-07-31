using Xunit;

namespace Telegram.OpenIdConnect.AspNetCore.Tests;

/// <summary>
/// Covers the identity overload added in 1.1.0: the library must hand the gate the username and
/// display name from the validated id_token, and a gate written against 1.0.0 (id-only) must keep
/// working untouched through the interface's default implementation.
/// </summary>
public sealed class GateIdentityTests
{
    private const long AllowedId = 335615025L;

    /// <summary>Records what the library passed, so the test can assert on the whole identity.</summary>
    private sealed class CapturingGate : ITelegramSignInGate
    {
        public TelegramSignInIdentity? Seen { get; private set; }

        // Never called by the library once the identity overload is implemented; failing loudly here
        // is what proves the library stopped using the id-only path.
        public ValueTask<TelegramSignInDecision> DecideAsync(long telegramUserId, CancellationToken ct) =>
            throw new InvalidOperationException("library must call the identity overload");

        public ValueTask<TelegramSignInDecision> DecideAsync(TelegramSignInIdentity identity, CancellationToken ct)
        {
            Seen = identity;
            return ValueTask.FromResult(new TelegramSignInDecision(identity.TelegramUserId == AllowedId));
        }
    }

    /// <summary>A 1.0.0-era gate: implements only the id-only overload and knows nothing about identity.</summary>
    private sealed class LegacyIdOnlyGate : ITelegramSignInGate
    {
        public long? Seen { get; private set; }

        public ValueTask<TelegramSignInDecision> DecideAsync(long telegramUserId, CancellationToken ct)
        {
            Seen = telegramUserId;
            return ValueTask.FromResult(new TelegramSignInDecision(telegramUserId == AllowedId));
        }
    }

    [Fact]
    public async Task IdentityOverload_ReceivesUsernameAndDisplayName()
    {
        CapturingGate gate = new();
        FakeAuditSink sink = new();
        using TelegramOidcTestHost host = new(gate, sink);

        using HttpResponseMessage response = await host.SignInAsync(
            AllowedId.ToString(), username: "platonenkov", displayName: "Aleksandr");

        Assert.NotNull(gate.Seen);
        Assert.Equal(AllowedId, gate.Seen!.TelegramUserId);
        Assert.Equal("platonenkov", gate.Seen.Username);
        Assert.Equal("Aleksandr", gate.Seen.DisplayName);
        Assert.Contains(response.Headers.GetValues("Set-Cookie"), c => c.Contains("TelegramCookie", StringComparison.Ordinal));
    }

    [Fact]
    public async Task LegacyIdOnlyGate_StillWorks_ViaDefaultImplementation()
    {
        LegacyIdOnlyGate gate = new();
        FakeAuditSink sink = new();
        using TelegramOidcTestHost host = new(gate, sink);

        using HttpResponseMessage response = await host.SignInAsync(
            AllowedId.ToString(), username: "platonenkov", displayName: "Aleksandr");

        Assert.Equal(AllowedId, gate.Seen);
        Assert.Contains(response.Headers.GetValues("Set-Cookie"), c => c.Contains("TelegramCookie", StringComparison.Ordinal));
        Assert.Equal(TelegramSignInOutcome.Success, Assert.Single(sink.Events).Outcome);
    }

    [Fact]
    public async Task DefaultImplementation_ForwardsToIdOnlyOverload()
    {
        LegacyIdOnlyGate gate = new();
        ITelegramSignInGate viaInterface = gate;

        // No host, no OIDC: the interface default alone must reach the id-only method.
        TelegramSignInDecision decision = await viaInterface
            .DecideAsync(new TelegramSignInIdentity(AllowedId, "ignored", "ignored"), CancellationToken.None);

        Assert.True(decision.Allowed);
        Assert.Equal(AllowedId, gate.Seen);
    }

    [Fact]
    public void Identity_UsernameAndDisplayName_AreOptional()
    {
        TelegramSignInIdentity identity = new(AllowedId);

        Assert.Equal(AllowedId, identity.TelegramUserId);
        Assert.Null(identity.Username);
        Assert.Null(identity.DisplayName);
    }
}
