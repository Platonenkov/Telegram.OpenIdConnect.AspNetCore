using System.Collections.Concurrent;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Telegram.OpenIdConnect.AspNetCore.Tests;

/// <summary>
/// The Telegram id, username and client IP are personal data: by default they must not reach the
/// application log, only the audit sink. <see cref="TelegramOidcOptions.LogPersonalData"/> opts in.
/// </summary>
public sealed class PersonalDataLoggingTests
{
    private const long AllowedId = 1000000001L;
    private const long UnknownId = 999000111L;

    [Theory]
    [InlineData(AllowedId)]
    [InlineData(UnknownId)]
    public async Task Default_LogsNoIdUsernameOrIp(long telegramId)
    {
        CapturingLoggerProvider logs = new();
        FakeAuditSink sink = new();
        using TelegramOidcTestHost host = new(
            new FakeSignInGate(AllowedId),
            sink,
            configureServices: s => s.AddSingleton<ILoggerProvider>(logs));

        using HttpResponseMessage response = await host.SignInAsync(telegramId.ToString());

        string[] lines = logs.Messages.ToArray();
        Assert.NotEmpty(lines);
        Assert.DoesNotContain(lines, l => l.Contains(telegramId.ToString(), StringComparison.Ordinal));
        Assert.DoesNotContain(lines, l => l.Contains(TelegramOidcTestHost.DefaultUsername, StringComparison.Ordinal));
        Assert.DoesNotContain(lines, l => l.Contains(TelegramOidcTestHost.PinnedRemoteIp, StringComparison.Ordinal));

        // The audit sink is unaffected by the logging switch.
        TelegramSignInAuditEvent e = Assert.Single(sink.Events);
        Assert.Equal(telegramId, e.TelegramUserId);
        Assert.Equal(TelegramOidcTestHost.DefaultUsername, e.Username);
        Assert.Equal(TelegramOidcTestHost.PinnedRemoteIp, e.ClientIp);
    }

    [Theory]
    [InlineData(AllowedId)]
    [InlineData(UnknownId)]
    public async Task OptIn_LogsIdUsernameAndIp(long telegramId)
    {
        CapturingLoggerProvider logs = new();
        using TelegramOidcTestHost host = new(
            new FakeSignInGate(AllowedId),
            configure: o => o.LogPersonalData = true,
            configureServices: s => s.AddSingleton<ILoggerProvider>(logs));

        using HttpResponseMessage response = await host.SignInAsync(telegramId.ToString());

        Assert.Contains(logs.Messages, l =>
            l.Contains(telegramId.ToString(), StringComparison.Ordinal) &&
            l.Contains(TelegramOidcTestHost.DefaultUsername, StringComparison.Ordinal) &&
            l.Contains(TelegramOidcTestHost.PinnedRemoteIp, StringComparison.Ordinal));
    }

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        public ConcurrentQueue<string> Messages { get; } = new();

        public ILogger CreateLogger(string categoryName) =>
            string.Equals(categoryName, "TelegramOidc", StringComparison.Ordinal)
                ? new CapturingLogger(Messages)
                : Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance;

        public void Dispose()
        {
        }
    }

    private sealed class CapturingLogger(ConcurrentQueue<string> messages) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            messages.Enqueue(formatter(state, exception));
    }
}
