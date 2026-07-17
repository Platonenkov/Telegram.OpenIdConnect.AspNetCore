namespace Telegram.OpenIdConnect.AspNetCore;

/// <summary>Result of one Telegram sign-in attempt.</summary>
public enum TelegramSignInOutcome
{
    /// <summary>The sign-in gate allowed the user and the sign-in cookie was issued.</summary>
    Success,

    /// <summary>The sign-in gate rejected the user.</summary>
    Denied,

    /// <summary>The OIDC flow failed before the sign-in gate could be evaluated.</summary>
    Failure,
}

/// <summary>One sign-in attempt. Profile fields are null when absent or on remote failure.</summary>
public sealed record TelegramSignInAuditEvent(
    TelegramSignInOutcome Outcome,
    long? TelegramUserId,
    string? Username,      // preferred_username
    string? DisplayName,   // name
    string? PictureUrl,    // picture
    string? ClientIp,
    string? Detail);       // failure reason

/// <summary>
/// Optional host-supplied audit persistence. If not registered, the library only logs. Implementations
/// MUST NOT throw — the library wraps calls, but a throwing sink still wastes work. Persist and swallow.
/// </summary>
public interface ITelegramSignInAuditSink
{
    /// <summary>Persists one sign-in attempt. Must not throw; the library treats a failure as best-effort loss.</summary>
    ValueTask RecordAsync(TelegramSignInAuditEvent e, CancellationToken ct);
}
