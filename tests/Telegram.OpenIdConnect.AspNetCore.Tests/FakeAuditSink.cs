using System.Collections.Concurrent;

namespace Telegram.OpenIdConnect.AspNetCore.Tests;

/// <summary>In-memory audit sink; tests assert against <see cref="Events"/>.</summary>
public sealed class FakeAuditSink : ITelegramSignInAuditSink
{
    public ConcurrentQueue<TelegramSignInAuditEvent> Events { get; } = new();

    public ValueTask RecordAsync(TelegramSignInAuditEvent e, CancellationToken ct)
    {
        Events.Enqueue(e);
        return ValueTask.CompletedTask;
    }
}
