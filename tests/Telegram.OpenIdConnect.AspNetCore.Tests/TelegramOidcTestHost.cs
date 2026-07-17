using System.Globalization;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Telegram.OpenIdConnect.AspNetCore.Tests;

/// <summary>
/// In-process host for the real Telegram OIDC middleware, with Telegram itself fully stubbed:
/// discovery is pinned to a hand-built <see cref="OpenIdConnectConfiguration"/> (no MetadataAddress,
/// so the handler never reaches the network), the code-&gt;token backchannel is a substitute
/// <see cref="HttpMessageHandler"/>, and id_tokens are self-signed with a key only this class knows.
/// Mirrors the end-to-end OIDC-stubbing approach used to validate this flow, minus the database: the
/// sign-in gate and audit sink are in-memory fakes supplied by the caller, so no Docker is required.
/// </summary>
public sealed class TelegramOidcTestHost : IDisposable
{
    /// <summary>
    /// The inline app pins Connection.RemoteIpAddress to this via middleware placed BEFORE
    /// UseAuthentication. TestServer otherwise leaves it null, which would let the default-IP test
    /// pass vacuously.
    /// </summary>
    public const string PinnedRemoteIp = "198.51.100.5";

    private const string TestClientId = "9000001";
    private const string Issuer = "https://oauth.telegram.org";
    private const string AuthEndpoint = "https://oauth.telegram.org/auth";
    private const string TokenEndpoint = "https://oauth.telegram.org/token";
    private const string SigningKid = "oidc-test-kid";
    private const string AccessToken = "test-access-token";

    private readonly ECDsa _signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly IHost _host;
    private readonly TestServer _server;
    private readonly List<HttpClient> _clients = [];

    // The id_token the stubbed token endpoint returns for the code exchange. Set per call to
    // SignInAsync AFTER the challenge, once the middleware-generated nonce is known (it must be
    // echoed into the id_token).
    private string? _stubIdToken;

    public TelegramOidcTestHost(
        ITelegramSignInGate gate,
        ITelegramSignInAuditSink? sink = null,
        Action<TelegramOidcOptions>? configure = null)
    {
        void EffectiveConfigure(TelegramOidcOptions options)
        {
            options.ClientId = TestClientId;
            options.ClientSecret = "test-secret";
            configure?.Invoke(options);
        }

        // Probe the effective scheme name outside DI so the PostConfigure stub below targets the
        // same named OpenIdConnectOptions instance AddTelegramOidc registers.
        TelegramOidcOptions probe = new();
        EffectiveConfigure(probe);
        string oidcScheme = probe.OidcScheme;

        IHostBuilder hostBuilder = new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddLogging();
                    services.AddDataProtection();
                    services.AddAntiforgery();
                    // The library no longer registers authorization (that is now the host's job, since
                    // only the host knows what policy — if any — its gate's claims should back). This
                    // test host stands in for that host, so it registers authorization itself; app.
                    // UseAuthorization() below needs the services regardless of whether any policy is
                    // actually evaluated.
                    services.AddAuthorization();

                    services.AddSingleton(gate);
                    if (sink is not null)
                    {
                        services.AddSingleton(sink);
                    }

                    services.AddTelegramOidc(EffectiveConfigure);

                    // Pin discovery to the stub and drop MetadataAddress, so the middleware NEVER
                    // reaches out to real Telegram (which would return its own signing keys and
                    // make id_token signature validation non-deterministic under network access).
                    services.PostConfigure<OpenIdConnectOptions>(oidcScheme, oidc =>
                    {
                        oidc.MetadataAddress = null;

                        OpenIdConnectConfiguration stubConfiguration = new()
                        {
                            Issuer = Issuer,
                            AuthorizationEndpoint = AuthEndpoint,
                            TokenEndpoint = TokenEndpoint,
                            JwksUri = Issuer + "/.well-known/jwks.json",
                        };
                        stubConfiguration.SigningKeys.Add(new ECDsaSecurityKey(_signingKey) { KeyId = SigningKid });

                        oidc.Configuration = stubConfiguration;
                        oidc.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(stubConfiguration);

                        // Discovery + ClientId supply these at runtime against real Telegram; pin
                        // them here since we stub the discovery document.
                        oidc.TokenValidationParameters.ValidIssuer = Issuer;
                        oidc.TokenValidationParameters.ValidAudience = TestClientId;

                        // Backchannel stub: return the per-call minted id_token for the code
                        // exchange, so no network call happens and the middleware validates a
                        // token we control end-to-end.
                        oidc.Backchannel = new HttpClient(new StubTokenHandler(TokenEndpoint, () => _stubIdToken));
                    });
                });

                webHost.Configure(app =>
                {
                    app.Use(async (context, next) =>
                    {
                        context.Connection.RemoteIpAddress = IPAddress.Parse(PinnedRemoteIp);
                        await next();
                    });

                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseAuthorization();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapTelegramOidcEndpoints();
                        // Test-only introspection endpoint: exposes the signed-in principal's claims
                        // as JSON so SignInAndReadPrincipalAsync can assert on them. Not part of the
                        // library's own surface.
                        endpoints.MapGet("/whoami", (HttpContext http) =>
                            Results.Json(http.User.Claims.Select(c => new { c.Type, c.Value })));
                    });
                });
            });

        _host = hostBuilder.Start();
        _server = _host.GetTestServer();
    }

    public HttpClient CreateClient(bool allowAutoRedirect = false)
    {
        HttpMessageHandler inner = _server.CreateHandler();
        CookieRelayHandler handler = new(inner, allowAutoRedirect);
        HttpClient client = new(handler) { BaseAddress = new Uri("https://localhost/") };
        _clients.Add(client);
        return client;
    }

    /// <summary>
    /// Drives challenge -> Telegram -> callback and returns the callback response.
    /// A null <paramref name="idClaim"/> mints a token with NO id claim (the fail-closed case).
    /// </summary>
    public async Task<HttpResponseMessage> SignInAsync(
        string? idClaim,
        string subClaim = "telegram-oidc-subject",
        Dictionary<string, string>? extraHeaders = null)
    {
        HttpClient client = CreateClient(allowAutoRedirect: false);

        using HttpRequestMessage challengeRequest = new(HttpMethod.Get, "/signin-telegram/challenge?returnUrl=/");
        ApplyHeaders(challengeRequest, extraHeaders);
        using HttpResponseMessage challenge = await client.SendAsync(challengeRequest).ConfigureAwait(false);
        if (challenge.StatusCode != HttpStatusCode.Redirect || challenge.Headers.Location is null)
        {
            throw new InvalidOperationException(
                $"Expected a redirect to Telegram from the challenge endpoint, got {challenge.StatusCode}.");
        }

        Dictionary<string, StringValues> query = QueryHelpers.ParseQuery(challenge.Headers.Location.Query);
        string state = query["state"].ToString();
        string nonce = query["nonce"].ToString();

        _stubIdToken = MintIdToken(subClaim, idClaim, nonce);

        using HttpRequestMessage callbackRequest = new(
            HttpMethod.Get,
            $"/signin-telegram?code=test-auth-code&state={Uri.EscapeDataString(state)}");
        ApplyHeaders(callbackRequest, extraHeaders);
        return await client.SendAsync(callbackRequest).ConfigureAwait(false);
    }

    /// <summary>
    /// Drives the same challenge -> Telegram -> callback flow as <see cref="SignInAsync"/>, then reads
    /// the resulting principal back via the test-only <c>/whoami</c> endpoint on the SAME client, so
    /// the sign-in cookie set on the callback response is relayed. Throws if the callback did not
    /// result in an authenticated session (e.g. the gate denied the sign-in).
    /// </summary>
    public async Task<ClaimsPrincipal> SignInAndReadPrincipalAsync(
        string idClaim,
        string subClaim = "telegram-oidc-subject")
    {
        HttpClient client = CreateClient(allowAutoRedirect: false);

        using HttpRequestMessage challengeRequest = new(HttpMethod.Get, "/signin-telegram/challenge?returnUrl=/");
        using HttpResponseMessage challenge = await client.SendAsync(challengeRequest).ConfigureAwait(false);
        if (challenge.StatusCode != HttpStatusCode.Redirect || challenge.Headers.Location is null)
        {
            throw new InvalidOperationException(
                $"Expected a redirect to Telegram from the challenge endpoint, got {challenge.StatusCode}.");
        }

        Dictionary<string, StringValues> query = QueryHelpers.ParseQuery(challenge.Headers.Location.Query);
        string state = query["state"].ToString();
        string nonce = query["nonce"].ToString();

        _stubIdToken = MintIdToken(subClaim, idClaim, nonce);

        using HttpRequestMessage callbackRequest = new(
            HttpMethod.Get,
            $"/signin-telegram?code=test-auth-code&state={Uri.EscapeDataString(state)}");
        using HttpResponseMessage callback = await client.SendAsync(callbackRequest).ConfigureAwait(false);
        if (callback.StatusCode != HttpStatusCode.Redirect ||
            !callback.Headers.TryGetValues("Set-Cookie", out IEnumerable<string>? setCookies) ||
            !setCookies.Any(c => c.Contains("TelegramCookie", StringComparison.Ordinal)))
        {
            throw new InvalidOperationException(
                $"Expected sign-in to succeed and set the auth cookie, got {callback.StatusCode}.");
        }

        using HttpRequestMessage whoamiRequest = new(HttpMethod.Get, "/whoami");
        using HttpResponseMessage whoamiResponse = await client.SendAsync(whoamiRequest).ConfigureAwait(false);
        whoamiResponse.EnsureSuccessStatusCode();

        string json = await whoamiResponse.Content.ReadAsStringAsync().ConfigureAwait(false);
        return ParsePrincipal(json);
    }

    /// <summary>Parses the <c>/whoami</c> JSON payload (an array of {type, value}) into a principal.</summary>
    private static ClaimsPrincipal ParsePrincipal(string json)
    {
        using JsonDocument document = JsonDocument.Parse(json);
        List<Claim> claims = [];
        foreach (JsonElement element in document.RootElement.EnumerateArray())
        {
            string type = element.GetProperty("type").GetString()!;
            string value = element.GetProperty("value").GetString()!;
            claims.Add(new Claim(type, value));
        }

        ClaimsIdentity identity = new(claims, authenticationType: "TestAuth");
        return new ClaimsPrincipal(identity);
    }

    public void Dispose()
    {
        foreach (HttpClient client in _clients)
        {
            client.Dispose();
        }

        _host.Dispose();
        _signingKey.Dispose();
    }

    private static void ApplyHeaders(HttpRequestMessage request, Dictionary<string, string>? headers)
    {
        if (headers is null)
        {
            return;
        }

        foreach (KeyValuePair<string, string> header in headers)
        {
            request.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }
    }

    /// <summary>
    /// Mints a self-signed id_token shaped like Telegram's real one: <paramref name="sub"/> is
    /// Telegram's own opaque OIDC subject and <paramref name="id"/> — when supplied — is the
    /// separate Bot-API user id the sign-in gate actually keys on. Pass <c>id: null</c> to mint a
    /// token missing the <c>id</c> claim entirely (exercises the fail-closed path).
    /// </summary>
    private string MintIdToken(string sub, string? id, string nonce)
    {
        DateTime now = DateTime.UtcNow;
        Dictionary<string, object> claims = new()
        {
            ["sub"] = sub,
            ["nonce"] = nonce,
            ["at_hash"] = ComputeAtHash(AccessToken),
            ["name"] = "Test Operator",
            ["preferred_username"] = "test_operator",
        };
        if (id is not null)
        {
            claims["id"] = long.Parse(id, CultureInfo.InvariantCulture);
        }

        SecurityTokenDescriptor descriptor = new()
        {
            Issuer = Issuer,
            Audience = TestClientId,
            IssuedAt = now,
            NotBefore = now.AddMinutes(-1),
            Expires = now.AddMinutes(5),
            Claims = claims,
            SigningCredentials = new SigningCredentials(
                new ECDsaSecurityKey(_signingKey) { KeyId = SigningKid }, SecurityAlgorithms.EcdsaSha256),
        };

        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    /// <summary>at_hash = base64url(left-most half of SHA-256(access_token)) — ES256 uses SHA-256.</summary>
    private static string ComputeAtHash(string accessToken)
    {
        byte[] hash = SHA256.HashData(Encoding.ASCII.GetBytes(accessToken));
        return Base64UrlEncoder.Encode(hash, 0, hash.Length / 2);
    }

    /// <summary>Returns the per-call minted id_token for any POST to the OIDC token endpoint.</summary>
    private sealed class StubTokenHandler : HttpMessageHandler
    {
        private readonly string _tokenEndpoint;
        private readonly Func<string?> _idTokenProvider;

        public StubTokenHandler(string tokenEndpoint, Func<string?> idTokenProvider)
        {
            _tokenEndpoint = tokenEndpoint;
            _idTokenProvider = idTokenProvider;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.RequestUri is not null &&
                request.RequestUri.AbsoluteUri.StartsWith(_tokenEndpoint, StringComparison.Ordinal))
            {
                string idToken = _idTokenProvider() ?? throw new InvalidOperationException("stub id_token not set");
                string json = $"{{\"token_type\":\"Bearer\",\"access_token\":\"{AccessToken}\",\"id_token\":\"{idToken}\",\"expires_in\":3600}}";
                HttpResponseMessage ok = new(HttpStatusCode.OK)
                {
                    Content = new StringContent(json, Encoding.UTF8, "application/json"),
                };
                return Task.FromResult(ok);
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }

    /// <summary>
    /// Relays cookies between requests issued through the same <see cref="HttpClient"/> (the state
    /// and nonce cookies set on the challenge response must be echoed back on the callback request)
    /// without touching response headers, so raw Set-Cookie stays visible to callers. Optionally
    /// follows redirects, since TestServer's in-memory handler does not do this on its own.
    /// </summary>
    private sealed class CookieRelayHandler : DelegatingHandler
    {
        private const int MaxRedirects = 5;

        private readonly CookieContainer _cookies = new();
        private readonly bool _allowAutoRedirect;

        public CookieRelayHandler(HttpMessageHandler inner, bool allowAutoRedirect) : base(inner) =>
            _allowAutoRedirect = allowAutoRedirect;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            HttpResponseMessage response = await SendOnceAsync(request, cancellationToken).ConfigureAwait(false);

            int redirects = 0;
            while (_allowAutoRedirect && IsRedirect(response.StatusCode) && response.Headers.Location is not null && redirects < MaxRedirects)
            {
                Uri nextUri = response.Headers.Location.IsAbsoluteUri
                    ? response.Headers.Location
                    : new Uri(request.RequestUri!, response.Headers.Location);
                response.Dispose();

                HttpRequestMessage redirected = new(HttpMethod.Get, nextUri);
                response = await SendOnceAsync(redirected, cancellationToken).ConfigureAwait(false);
                request = redirected;
                redirects++;
            }

            return response;
        }

        private async Task<HttpResponseMessage> SendOnceAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Uri uri = request.RequestUri!;
            string cookieHeader = _cookies.GetCookieHeader(uri);
            if (!string.IsNullOrEmpty(cookieHeader))
            {
                request.Headers.TryAddWithoutValidation("Cookie", cookieHeader);
            }

            HttpResponseMessage response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

            if (response.Headers.TryGetValues("Set-Cookie", out IEnumerable<string>? setCookies))
            {
                foreach (string setCookie in setCookies)
                {
                    try
                    {
                        _cookies.SetCookies(uri, setCookie);
                    }
                    catch (CookieException)
                    {
                        // Malformed cookie header segment — ignore, mirrors a browser's leniency.
                    }
                }
            }

            return response;
        }

        private static bool IsRedirect(HttpStatusCode statusCode) =>
            statusCode is HttpStatusCode.Redirect or HttpStatusCode.Moved
                or HttpStatusCode.RedirectMethod or HttpStatusCode.RedirectKeepVerb or HttpStatusCode.PermanentRedirect;
    }
}
