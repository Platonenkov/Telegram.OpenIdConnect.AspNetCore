# Telegram.OpenIdConnect.AspNetCore

Telegram OpenID Connect sign-in for ASP.NET Core.

Not a drop-in `AuthenticationHandler`. This is an opinionated sign-in flow: cookie auth + OIDC
wiring + a gate + an audit hook + two endpoints. If you want a bare handler to compose yourself,
this is not it.

> Not affiliated with, endorsed by, or sponsored by Telegram. "Telegram" is a trademark of
> Telegram Messenger Inc.; used here descriptively.

- [Server-side only](#server-side-only)
- [Install](#install)
- [BotFather setup](#botfather-setup)
- [Quickstart](#quickstart)
- [Complete minimal example](#complete-minimal-example)
- [The gate](#the-gate)
- [The audit sink](#the-audit-sink)
- [Reading the signed-in user](#reading-the-signed-in-user)
- [Endpoints](#endpoints)
- [Login page and logout](#login-page-and-logout)
- [Behind a reverse proxy](#behind-a-reverse-proxy)
- [Options](#options)
- [Gotchas](#gotchas)

## Server-side only

Telegram's OIDC discovery document lists no `none` in `token_endpoint_auth_methods_supported` —
every authorization-code→token exchange requires the client secret. That means public clients
(MAUI, Blazor WebAssembly, SPAs calling Telegram directly) **cannot** use this package, or any
direct Telegram OIDC client: there is no way to keep a client secret on a device you ship to
users. Put a confidential backend in front of them instead.

Blazor **Server** works fine — it's server-side ASP.NET Core, same as any other host here.

## Install

```bash
dotnet add package Telegram.OpenIdConnect.AspNetCore
```

## BotFather setup

1. Open `@BotFather`, pick your bot, and turn on **OIDC**. This is a toggle, not an addition — enabling
   it **replaces the legacy Login Widget on that bot**. You cannot run both on the same bot at once.
2. One Client ID can serve several Redirect URIs, so a single bot can back several apps
   (e.g. a staging and a production deployment) — register every callback URL you need with
   BotFather.
3. **Client ID** is the bot's numeric Bot ID (not secret — it's the `aud` of every id_token and
   the value the Login Widget already exposed).
4. **Client Secret** is issued by BotFather when you enable OIDC. Treat it like any other secret
   (configuration provider / secret manager — never source control).
5. **Redirect URI** is `https://<your-host><CallbackPath>`, where `CallbackPath` defaults to
   `/signin-telegram` (see [Options](#options)). Register the exact URI, scheme included — Telegram
   matches it literally.

## Quickstart

```csharp
builder.Services.AddTelegramOidc(o =>
{
    o.ClientId = builder.Configuration["TelegramOidc:ClientId"] ?? "";
    o.ClientSecret = builder.Configuration["TelegramOidc:ClientSecret"] ?? "";
    o.DefaultReturnUrl = "/dashboard";
});

builder.Services.AddScoped<ITelegramSignInGate, MyGate>();        // required
builder.Services.AddScoped<ITelegramSignInAuditSink, MySink>();   // optional

// The library does authentication; authorization is yours. Register your own policy:
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("Staff", p => p.RequireRole("Staff"));

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.MapTelegramOidcEndpoints();
```

**The `AddAuthorizationBuilder()`/`AddPolicy(...)` call above is required, not optional, if your
pipeline calls `app.UseAuthorization()`.** This library only wires *authentication* (who the caller
is); it does not call `services.AddAuthorization()` and does not register any policy. If
`UseAuthorization()` runs against a service collection that never had authorization services
registered, ASP.NET Core throws `InvalidOperationException` at startup. The library does
authentication; you own authorization — register it yourself or the app will not start.

## Complete minimal example

A runnable single-file app: one protected page, a login page, sign-in via Telegram, logout.

`appsettings.json` (or user-secrets / environment — anything but source control for the secret):

```json
{
  "TelegramOidc": {
    "ClientId": "8858161322",
    "ClientSecret": "<from BotFather>"
  }
}
```

`Program.cs`:

```csharp
using System.Security.Claims;

using Microsoft.AspNetCore.Antiforgery;

using Telegram.OpenIdConnect.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddTelegramOidc(o =>
{
    o.ClientId = builder.Configuration["TelegramOidc:ClientId"] ?? "";
    o.ClientSecret = builder.Configuration["TelegramOidc:ClientSecret"] ?? "";
    o.DefaultReturnUrl = "/";
});

builder.Services.AddScoped<ITelegramSignInGate, StaffGate>();

// Authorization is the host's job (see Quickstart). Antiforgery backs the logout endpoint;
// Razor Pages / MVC / Blazor register it already — a minimal API host adds it explicitly.
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("Staff", p => p.RequireRole("Staff"));
builder.Services.AddAntiforgery();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
app.MapTelegramOidcEndpoints();

app.MapGet("/", (ClaimsPrincipal user) =>
        Results.Text($"Hello, {user.Identity?.Name}!", "text/plain"))
    .RequireAuthorization("Staff");

app.MapGet("/login", (HttpContext http, IAntiforgery antiforgery) =>
{
    AntiforgeryTokenSet tokens = antiforgery.GetAndStoreTokens(http);
    string denied = http.Request.Query.ContainsKey("denied") ? "<p>Access denied.</p>" : "";
    string error = http.Request.Query.ContainsKey("error") ? "<p>Sign-in failed, try again.</p>" : "";
    return Results.Content($"""
        {denied}{error}
        <a href="/signin-telegram/challenge?returnUrl=/">Sign in with Telegram</a>
        <form method="post" action="/signin-telegram/logout">
            <input type="hidden" name="{tokens.FormFieldName}" value="{tokens.RequestToken}" />
            <button type="submit">Sign out</button>
        </form>
        """, "text/html");
});

app.Run();

sealed class StaffGate : ITelegramSignInGate
{
    private static readonly HashSet<long> Staff = [1000000001L, 1000000002L];

    public ValueTask<TelegramSignInDecision> DecideAsync(long telegramUserId, CancellationToken ct) =>
        ValueTask.FromResult(Staff.Contains(telegramUserId)
            ? new TelegramSignInDecision(true, [new Claim(ClaimTypes.Role, "Staff")])
            : new TelegramSignInDecision(false));
}
```

Run it, open `/`, get redirected to `/login`, click the link, confirm in Telegram, land back on `/`
as an authenticated user.

## The gate

The gate is the only place that decides who gets in and with what claims. The library never
consults an allow-list of its own and knows nothing about roles or permissions — that is entirely
the host's business.

```csharp
public sealed class MyGate : ITelegramSignInGate
{
    public ValueTask<TelegramSignInDecision> DecideAsync(long telegramUserId, CancellationToken ct) =>
        ValueTask.FromResult(telegramUserId == 12345678L
            ? new TelegramSignInDecision(true, [new Claim(ClaimTypes.Role, "Staff")])
            : new TelegramSignInDecision(false));
}
```

A gate is called on every successful token validation, keyed on the Telegram Bot-API user id (see
[Gotchas](#gotchas) for why that matters). Since 1.1.0 the library calls the
[identity overload](#matching-a-pending-username-invite-110), which by default forwards to the
id-only one above — so a gate like this keeps working untouched. Note the consequence if you
implement BOTH: the id-only method is then dead code as far as the library is concerned, because
the overload it actually calls no longer forwards to it.

The returned `TelegramSignInDecision` carries two things: `Allowed` (false rejects the sign-in
outright) and `Claims` (attached to the resulting principal verbatim — the library never inspects
or filters them). `new TelegramSignInDecision(true)` with no claims is also valid; you get a plain
authenticated user with no roles.

A database-backed gate is the same interface with your own store behind it — here with EF Core,
mapping per-user roles from a table:

```csharp
public sealed class DbGate : ITelegramSignInGate
{
    private readonly AppDbContext _db;

    public DbGate(AppDbContext db) => _db = db;

    public async ValueTask<TelegramSignInDecision> DecideAsync(long telegramUserId, CancellationToken ct)
    {
        AppUser? user = await _db.Users
            .AsNoTracking()
            .FirstOrDefaultAsync(u => u.TelegramId == telegramUserId && u.IsActive, ct);

        if (user is null)
        {
            return new TelegramSignInDecision(false);
        }

        List<Claim> claims = [new Claim(ClaimTypes.Role, user.Role)];
        return new TelegramSignInDecision(true, claims);
    }
}
```

### Matching a pending `@username` invite (1.1.0)

`DecideAsync(long, …)` answers "may this id in?", which is all a gate needs once the person has
signed in before. It is not enough the *first* time, when the invite was written before anyone
could know their numeric id:

```csharp
public sealed class InviteGate : ITelegramSignInGate
{
    // Never called by the library once the overload below exists; keep it for source compatibility.
    public ValueTask<TelegramSignInDecision> DecideAsync(long telegramUserId, CancellationToken ct) =>
        DecideAsync(new TelegramSignInIdentity(telegramUserId), ct);

    public async ValueTask<TelegramSignInDecision> DecideAsync(TelegramSignInIdentity identity, CancellationToken ct)
    {
        // Known id wins. Only if nothing matches, fall back to a pending invite by username and
        // back-fill the id, so the next sign-in resolves by id alone.
        AppUser? user = await _db.Users.FirstOrDefaultAsync(u => u.TelegramId == identity.TelegramUserId, ct);
        if (user is null && identity.Username is { Length: > 0 } name)
        {
            user = await _db.Users.FirstOrDefaultAsync(u => u.TelegramId == null && u.Username == name, ct);
            if (user is not null)
            {
                user.TelegramId = identity.TelegramUserId;
                await _db.SaveChangesAsync(ct);
            }
        }
        return user is null ? new(false) : new(true, [new Claim(ClaimTypes.Role, user.Role)]);
    }
}
```

**A username is not an identity.** Its owner can change or release it and Telegram may hand it to
someone else, so treat it only as a one-time bridge to a real id — never as the standing key for
access. `TelegramUserId` is the field to authorize on.

The identity overload has a default implementation that forwards to the id-only one, so gates
written against 1.0.0 keep compiling and behave exactly as before.

Register it scoped (`AddScoped<ITelegramSignInGate, DbGate>()`) so it can take a scoped `DbContext`.
Letting everyone in (`new TelegramSignInDecision(true)`) is also a legitimate gate — e.g. for a
public service where Telegram identity itself is the only requirement.

## The audit sink

Optional. When registered, the library reports every sign-in attempt — success, gate denial, or
flow failure — with the Telegram profile fields it saw and the client IP. When not registered, the
library only logs. A sink failure never breaks sign-in: the call is wrapped, worst case you lose
one audit row.

```csharp
public sealed class DbAuditSink : ITelegramSignInAuditSink
{
    private readonly AppDbContext _db;

    public DbAuditSink(AppDbContext db) => _db = db;

    public async ValueTask RecordAsync(TelegramSignInAuditEvent e, CancellationToken ct)
    {
        _db.SignInAudit.Add(new SignInAuditRow
        {
            OccurredAt = DateTimeOffset.UtcNow,
            Outcome = e.Outcome.ToString(),      // Success | Denied | Failure
            TelegramUserId = e.TelegramUserId,   // null when the flow failed before identification
            Username = e.Username,               // preferred_username
            DisplayName = e.DisplayName,         // name
            PictureUrl = e.PictureUrl,           // picture
            ClientIp = e.ClientIp,
            Detail = e.Detail,                   // failure reason, e.g. "rejected by gate"
        });
        await _db.SaveChangesAsync(ct);
    }
}
```

The three outcomes: `Success` (gate allowed, cookie issued), `Denied` (gate rejected a validated
Telegram user), `Failure` (the flow broke before the gate — missing `id` claim, remote error,
user cancelled at Telegram; profile fields may be null). If you store these rows, remember they
contain personal data — plan retention accordingly.

## Reading the signed-in user

The library sets `MapInboundClaims = false`, so claims keep their raw OIDC names. After sign-in
the principal carries Telegram's profile claims, whatever your gate attached, and one claim the
library always adds — `telegram_user_id`:

```csharp
app.MapGet("/me", (ClaimsPrincipal user) =>
{
    long telegramId = long.Parse(user.FindFirstValue("telegram_user_id")!);
    string? username = user.Identity?.Name;                  // preferred_username (NameClaimType)
    string? displayName = user.FindFirstValue("name");
    string? pictureUrl = user.FindFirstValue("picture");

    return Results.Ok(new { telegramId, username, displayName, pictureUrl });
}).RequireAuthorization();
```

`telegram_user_id` is the stable Bot-API id — use it as your foreign key, not `sub`
(see [Gotchas](#gotchas)).

## Endpoints

`MapTelegramOidcEndpoints()` maps two endpoints under `CallbackPath` (default `/signin-telegram`),
plus the callback path itself is intercepted by the OIDC handler:

| Method | Path | Purpose |
|---|---|---|
| `GET` | `{CallbackPath}/challenge?returnUrl=...` | Starts the sign-in flow — redirects to Telegram. Returns `503` if unconfigured (see Gotchas). |
| `POST` | `{CallbackPath}/logout` | Signs the local cookie out. Requires a valid antiforgery token; otherwise `400`. |
| `GET` | `{CallbackPath}` | The OIDC authorization-code callback, handled internally by the OpenID Connect handler — not something you call directly. |

`returnUrl` is only honored when it is a local path (a single leading `/`); anything else —
absolute URLs, protocol-relative `//`, backslash tricks — falls back to `DefaultReturnUrl`, so the
challenge endpoint cannot be used as an open redirector.

## Login page and logout

This package ships no UI. Build whatever login page fits your app and point it at the challenge
endpoint:

```html
<a href="/signin-telegram/challenge?returnUrl=/dashboard">Sign in with Telegram</a>
```

Handle the two query-string outcomes the library redirects back with on failure:

- `?denied=1` — the sign-in gate rejected the user (`AccessDeniedPath`, default
  `/login?denied=1`).
- `?error=1` — the OIDC flow itself failed (missing `id` claim, remote failure, access-denied
  response from Telegram) and got redirected to `LoginPath + "?error=1"`.

Logout is a POST guarded by an antiforgery token. In Razor Pages / MVC the form tag helper emits
the token automatically:

```html
<form method="post" action="/signin-telegram/logout">
    <button type="submit">Sign out</button>
</form>
```

Outside of tag helpers (minimal APIs, hand-written HTML), obtain the token from `IAntiforgery`
and include it as a hidden field — the [Complete minimal example](#complete-minimal-example)
shows the full pattern. Antiforgery services must be registered (`services.AddAntiforgery()`);
Razor Pages / MVC / Blazor already do this, a bare minimal-API host does not.

## Behind a reverse proxy

Two separate concerns when nginx (or any reverse proxy) fronts your app:

**1. Scheme.** Telegram matches the Redirect URI literally, scheme included. If TLS terminates at
the proxy, the app must see `https` or the generated `redirect_uri` will be `http://...` and
Telegram will reject it. Standard forwarded-headers middleware solves this:

```csharp
app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto,
    // Behind Docker the proxy connects from the bridge network, not loopback:
    KnownNetworks = { },   // then .Clear() both lists if your proxy IP is not known statically
});
```

**2. Audited client IP.** By default the library records `Connection.RemoteIpAddress` and trusts
no header. If — and only if — your proxy *unconditionally overwrites* a header with the real
client address, opt in:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header X-Real-IP $remote_addr;   # overwritten on every request — not forwardable by clients
}
```

```csharp
builder.Services.AddTelegramOidc(o =>
{
    // Safe ONLY because nginx above overwrites X-Real-IP unconditionally.
    o.ClientIpResolver = http =>
        http.Request.Headers.TryGetValue("X-Real-IP", out var ip) && !string.IsNullOrWhiteSpace(ip)
            ? ip.ToString().Trim()
            : http.Connection.RemoteIpAddress?.ToString();
});
```

The library normalizes IPv4-mapped IPv6 (`::ffff:1.2.3.4` → `1.2.3.4`) on top of whatever the
resolver returns, so audit rows stay consistent. Never read a forwarded header without such a
proxy — see [Gotchas](#gotchas).

## Options

All properties of `TelegramOidcOptions`, configured via the `AddTelegramOidc(o => ...)` delegate:

| Property | Default | Meaning |
|---|---|---|
| `ClientId` | `""` | Telegram Bot ID (OIDC `client_id`, and `id_token` `aud`). Empty means unconfigured — see Gotchas. |
| `ClientSecret` | `""` | Telegram Bot token (OIDC `client_secret`). Empty means unconfigured. |
| `MetadataAddress` | `https://oauth.telegram.org/.well-known/openid-configuration` | OIDC discovery document address. |
| `CallbackPath` | `/signin-telegram` | Path the OIDC handler intercepts for the authorization-code callback. Also the base path for `/challenge` and `/logout`. |
| `LoginPath` | `/login` | Path the cookie handler redirects to when authentication is required. |
| `AccessDeniedPath` | `/login?denied=1` | Where a denied sign-in is redirected (issued by the sign-in flow; also used as the cookie scheme's `AccessDeniedPath` for authorization denials). |
| `CookieScheme` | `TelegramCookie` | Name of the cookie authentication scheme this library registers. |
| `OidcScheme` | `TelegramOidc` | Name of the OpenID Connect authentication scheme this library registers. |
| `CookieTtlHours` | `12` | Sliding expiration window, in hours, for the sign-in cookie. |
| `DefaultReturnUrl` | `/` | Landing page after sign-in when the challenge carries no (safe) `returnUrl`. |
| `ClientIpResolver` | `null` | Resolves the client IP recorded in the audit trail. `null` uses `HttpContext.Connection.RemoteIpAddress`. Supply a resolver only when a reverse proxy in front of you overwrites the forwarded header unconditionally — see Gotchas. |

## Gotchas

Everything below was found by running against `oauth.telegram.org` — none of it is documented by
Telegram.

- **`sub` is not the Bot-API user id.** Telegram's OIDC `sub` is its own subject identifier; the
  Bot-API id — the one the Login Widget used to deliver, the one your allow-list is keyed on —
  arrives in a separate `id` claim. This package keys the gate on `id` and never falls back to
  `sub`.
- **`state` is capped at 256 chars.** Telegram's authorize endpoint hard-rejects longer state with
  a plain-text `state too long`. ASP.NET Core's default `PropertiesDataFormat` emits ~500 chars
  inline. This package stores the protected payload in a short-lived, single-use cookie and puts a
  ~22-char id on the wire instead.
- **Telegram answers gzip unsolicited.** `oauth.telegram.org` intermittently returns
  `Content-Encoding: gzip` even when the request carried no `Accept-Encoding` (measured
  2026-07-16: 4 of 10 responses). Without decompression, discovery/JWKS fail with IDX20803/IDX10805
  and challenges 500 at random. This package forces `AutomaticDecompression`.
- **Don't trust forwarded headers without a proxy that overwrites them.** The default
  `ClientIpResolver` reads `RemoteIpAddress` and trusts no header. Only supply a header-reading
  resolver when a reverse proxy in front of you sets that header unconditionally — otherwise it's
  attacker-controlled and any client can stamp an arbitrary IP into your audit trail.
- **Unconfigured is not broken.** Leave `ClientId`/`ClientSecret` empty and the app still starts
  and stays healthy; only `{CallbackPath}/challenge` returns `503`. Handy when sign-in is
  optional in some environments.
- **`AddAuthorization()` is on you, and it's required if you call `UseAuthorization()`.** This
  library registers authentication only — no `services.AddAuthorization()`, no policy. If your
  pipeline runs `app.UseAuthorization()` without authorization services registered somewhere
  (yours, not the library's), ASP.NET Core throws `InvalidOperationException` at startup. Register
  `AddAuthorizationBuilder().AddPolicy(...)` (or plain `AddAuthorization()`) yourself, as shown in
  Quickstart.
- **Logout needs antiforgery services.** The logout endpoint resolves `IAntiforgery` from DI.
  Razor Pages / MVC / Blazor register it as part of their own setup; a bare minimal-API host must
  call `services.AddAntiforgery()` itself, or the first logout request fails to resolve the
  service.

## License

MIT.
