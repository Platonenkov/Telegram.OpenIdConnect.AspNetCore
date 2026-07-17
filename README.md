# Telegram.OpenIdConnect.AspNetCore

Telegram OpenID Connect sign-in for ASP.NET Core.

Not a drop-in `AuthenticationHandler`. This is an opinionated sign-in flow: cookie auth + OIDC
wiring + a gate + an audit hook + two endpoints. If you want a bare handler to compose yourself,
this is not it.

> Not affiliated with, endorsed by, or sponsored by Telegram. "Telegram" is a trademark of
> Telegram Messenger Inc.; used here descriptively.

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

`DecideAsync` is called on every successful token validation, keyed on the Telegram Bot-API user
id (see [Gotchas](#gotchas) for why that matters). The returned `TelegramSignInDecision` carries
two things: `Allowed` (false rejects the sign-in outright) and `Claims` (attached to the resulting
principal verbatim — the library never inspects or filters them). `new TelegramSignInDecision(true)`
with no claims is also valid; you get a plain authenticated user with no roles.

## Endpoints

`MapTelegramOidcEndpoints()` maps two endpoints under `CallbackPath` (default `/signin-telegram`),
plus the callback path itself is intercepted by the OIDC handler:

| Method | Path | Purpose |
|---|---|---|
| `GET` | `{CallbackPath}/challenge?returnUrl=...` | Starts the sign-in flow — redirects to Telegram. Returns `503` if unconfigured (see Gotchas). |
| `POST` | `{CallbackPath}/logout` | Signs the local cookie out. Requires a valid antiforgery token; otherwise `400`. |
| `GET` | `{CallbackPath}` | The OIDC authorization-code callback, handled internally by the OpenID Connect handler — not something you call directly. |

## Login page

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

## License

MIT.
