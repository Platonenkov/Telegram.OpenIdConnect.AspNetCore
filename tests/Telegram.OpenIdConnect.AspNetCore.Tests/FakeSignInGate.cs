namespace Telegram.OpenIdConnect.AspNetCore.Tests;

/// <summary>In-memory gate: allows exactly the ids it was constructed with. No database, no Docker.</summary>
public sealed class FakeSignInGate : ITelegramSignInGate
{
    private readonly HashSet<long> _allowed;

    public FakeSignInGate(params long[] allowed) => _allowed = [.. allowed];

    public ValueTask<TelegramSignInDecision> DecideAsync(long telegramUserId, CancellationToken ct) =>
        ValueTask.FromResult(new TelegramSignInDecision(_allowed.Contains(telegramUserId)));
}
