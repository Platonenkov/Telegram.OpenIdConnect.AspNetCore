using Microsoft.AspNetCore.Http;

using Xunit;

namespace Telegram.OpenIdConnect.AspNetCore.Tests;

/// <summary>
/// The audit trail's client IP. The default must never trust a request header: without a proxy that
/// overwrites it, a header is attacker-controlled and would poison the audit trail. Hosts that DO
/// run such a proxy opt in explicitly via ClientIpResolver.
/// </summary>
public sealed class ClientIpResolverTests
{
    private const long AllowedId = 335615025L;

    /// <summary>
    /// Asserts the POSITIVE: the audited IP is the connection's, not the header's. Asserting merely
    /// "not 9.9.9.9" would pass on a null ClientIp and prove nothing — TestServer leaves
    /// RemoteIpAddress null unless something sets it, which is why the host pins it.
    /// </summary>
    [Fact]
    public async Task Default_IgnoresXRealIpHeader_AndUsesConnectionRemoteIp()
    {
        FakeAuditSink sink = new();
        using TelegramOidcTestHost host = new(new FakeSignInGate(AllowedId), sink);

        await host.SignInAsync(AllowedId.ToString(), extraHeaders: new() { ["X-Real-IP"] = "9.9.9.9" });

        TelegramSignInAuditEvent e = Assert.Single(sink.Events);
        Assert.Equal(TelegramOidcTestHost.PinnedRemoteIp, e.ClientIp);   // 198.51.100.5
    }

    [Fact]
    public async Task CustomResolver_IsUsed()
    {
        FakeAuditSink sink = new();
        using TelegramOidcTestHost host = new(
            new FakeSignInGate(AllowedId),
            sink,
            configure: o => o.ClientIpResolver = http =>
                http.Request.Headers.TryGetValue("X-Real-IP", out Microsoft.Extensions.Primitives.StringValues v)
                    ? v.ToString()
                    : null);

        await host.SignInAsync(AllowedId.ToString(), extraHeaders: new() { ["X-Real-IP"] = "203.0.113.7" });

        TelegramSignInAuditEvent e = Assert.Single(sink.Events);
        Assert.Equal("203.0.113.7", e.ClientIp);
    }

    /// <summary>
    /// The library normalizes IPv4-mapped IPv6 on top of whatever the resolver returned, so hosts
    /// never have to think about MapToIPv4.
    /// </summary>
    [Fact]
    public async Task ResolverResult_IsNormalizedFromIPv4MappedForm()
    {
        FakeAuditSink sink = new();
        using TelegramOidcTestHost host = new(
            new FakeSignInGate(AllowedId),
            sink,
            configure: o => o.ClientIpResolver = _ => "::ffff:172.18.0.1");

        await host.SignInAsync(AllowedId.ToString());

        TelegramSignInAuditEvent e = Assert.Single(sink.Events);
        Assert.Equal("172.18.0.1", e.ClientIp);
    }
}
