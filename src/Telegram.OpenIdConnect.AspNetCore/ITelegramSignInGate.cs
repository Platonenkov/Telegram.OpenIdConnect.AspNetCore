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
/// Who is trying to sign in, as Telegram described them in the validated id_token.
/// </summary>
/// <param name="TelegramUserId">
/// The Bot-API user id (the <c>id</c> claim). The only field a gate should key authorization on: it
/// is stable and the user cannot change it.
/// </param>
/// <param name="Username">
/// <c>preferred_username</c>, without a leading "@". Null when the account has none.
/// <para>
/// A username is NOT an identity — its owner can change or release it at any time, and Telegram may
/// then hand it to somebody else. Use it to reconcile a pending invite with a real id on first
/// sign-in, or for display; never as the sole basis for granting access.
/// </para>
/// </param>
/// <param name="DisplayName">The <c>name</c> claim. Display only.</param>
public sealed record TelegramSignInIdentity(
    long TelegramUserId,
    string? Username = null,
    string? DisplayName = null);

/// <summary>
/// Host-supplied decision point for Telegram sign-in. Called on every successful OIDC token
/// validation, keyed on the Bot-API user id (the <c>id</c> claim — never Telegram's OIDC <c>sub</c>).
/// </summary>
public interface ITelegramSignInGate
{
    /// <summary>Decides whether the given Telegram user id may sign in, and with which claims.</summary>
    ValueTask<TelegramSignInDecision> DecideAsync(long telegramUserId, CancellationToken ct);

    /// <summary>
    /// The overload the library actually calls. It adds the username and display name Telegram sent
    /// alongside the id, which an id-only signature cannot express: a host that pre-registers people
    /// by <c>@username</c> — before it can possibly know their numeric id — needs that username to
    /// match the pending record and back-fill the id on first sign-in.
    /// <para>
    /// Defaults to the id-only overload, so gates written against 1.0.0 keep compiling and behave
    /// exactly as before. Override this one to see the extra fields.
    /// </para>
    /// </summary>
    ValueTask<TelegramSignInDecision> DecideAsync(TelegramSignInIdentity identity, CancellationToken ct) =>
        DecideAsync(identity.TelegramUserId, ct);
}
