# Changelog

All notable changes to this package are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the package uses
[Semantic Versioning](https://semver.org/).

## [1.1.1] - Unreleased

### Security

- Fixed an open redirect through the challenge endpoint `{CallbackPath}/challenge`. The `returnUrl`
  check looked only at the first two characters, so a value such as `returnUrl=/%09/evil.test`
  (also `%0a`, `%0d`) passed and, after a successful sign-in, came back in the `Location` header with
  a raw tab or newline after the first `/`. Browsers drop those characters and followed the redirect
  to `//evil.test`. `returnUrl` is now accepted only when it starts with a single `/`, its path part
  has no `//`, and it contains no `\` and no control character (C0, DEL, C1), checked on the raw
  value and on every percent-decoded form of it. Anything else falls back to `DefaultReturnUrl`.

### Changed

- The sign-in and denied-sign-in log lines in the `TelegramOidc` category no longer include the
  Telegram id, username and client IP, which are personal data. The new
  `TelegramOidcOptions.LogPersonalData` option (default `false`) restores them. The audit sink still
  receives the full event.

## [1.1.0] - 2026-07-31

### Added

- The sign-in gate receives the username and display name alongside the Telegram id, so a host can
  reconcile a pending `@username` invite with a real id. Gates that implement only the id-only
  overload keep working unchanged.

## [1.0.0] - 2026-07-17

- First public release: Telegram OpenID Connect sign-in for ASP.NET Core with a sign-in gate,
  an audit sink, the challenge and logout endpoints, and `ClientIpResolver`.
