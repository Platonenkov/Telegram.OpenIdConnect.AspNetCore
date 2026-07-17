using System.Security.Claims;

namespace Telegram.OpenIdConnect.AspNetCore;

/// <summary>
/// The gate's verdict: whether this user may sign in, and which claims the resulting principal
/// carries. Claims are the host's business — the library attaches them verbatim and never inspects
/// them, so roles and permissions stay entirely out of this package.
/// </summary>
/// <param name="Allowed">False rejects the sign-in.</param>
/// <param name="Claims">Claims to attach. Null or empty means a plain authenticated user.</param>
public sealed record TelegramSignInDecision(
    bool Allowed,
    IReadOnlyCollection<Claim>? Claims = null);

/// <summary>
/// Host-supplied decision point for Telegram sign-in. Called on every successful OIDC token
/// validation, keyed on the Bot-API user id (the <c>id</c> claim — never Telegram's OIDC <c>sub</c>).
/// </summary>
public interface ITelegramSignInGate
{
    /// <summary>Decides whether the given Telegram user id may sign in, and with which claims.</summary>
    ValueTask<TelegramSignInDecision> DecideAsync(long telegramUserId, CancellationToken ct);
}
