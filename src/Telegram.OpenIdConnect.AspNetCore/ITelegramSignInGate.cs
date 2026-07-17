namespace Telegram.OpenIdConnect.AspNetCore;

/// <summary>
/// Host-supplied source of truth for which Telegram user ids may enter the admin. Called on every
/// successful OIDC token validation; a false result rejects the sign-in.
/// </summary>
public interface ITelegramSignInGate
{
    /// <summary>Returns whether the given Telegram user id may complete sign-in.</summary>
    ValueTask<bool> IsAllowedAsync(long telegramUserId, CancellationToken ct);
}
