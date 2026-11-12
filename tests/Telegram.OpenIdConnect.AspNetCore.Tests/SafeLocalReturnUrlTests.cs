using Telegram.OpenIdConnect.AspNetCore;

namespace Telegram.OpenIdConnect.AspNetCore.Tests;

public sealed class SafeLocalReturnUrlTests
{
    private const string Fallback = "/fallback";

    [Theory]
    [InlineData("/")]
    [InlineData("/dashboard/installs")]
    [InlineData("/dashboard/history?page=2")]
    [InlineData("/dashboard#section")]
    [InlineData("/search?q=a%20b")]
    [InlineData("/caf%C3%A9")]
    [InlineData("/go?next=https://example.com")]
    [InlineData("/go?next=//example.com")]
    public void AcceptsPlainLocalPaths(string input)
    {
        Assert.Equal(input, TelegramOidcEndpoints.SafeLocalReturnUrl(input, Fallback));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void EmptyFallsBack(string? input)
    {
        Assert.Equal(Fallback, TelegramOidcEndpoints.SafeLocalReturnUrl(input, Fallback));
    }

    [Theory]
    [InlineData("https://evil.test")]
    [InlineData("http://x")]
    [InlineData("javascript:alert(1)")]
    [InlineData("data:text/html,<script>alert(1)</script>")]
    [InlineData("evil.test")]
    [InlineData(" /dashboard")]
    public void RejectsAbsoluteAndRelativeNonPaths(string input)
    {
        Assert.Equal(Fallback, TelegramOidcEndpoints.SafeLocalReturnUrl(input, Fallback));
    }

    [Theory]
    [InlineData("//evil.test")]
    [InlineData("///evil.test")]
    [InlineData("/a//evil.test")]
    [InlineData("/%2Fevil.test")]
    [InlineData("/%2fevil.test")]
    [InlineData("%2F%2Fevil.test")]
    public void RejectsProtocolRelative(string input)
    {
        Assert.Equal(Fallback, TelegramOidcEndpoints.SafeLocalReturnUrl(input, Fallback));
    }

    [Theory]
    [InlineData("/\\evil.test")]
    [InlineData("\\\\evil.test")]
    [InlineData("/a\\b")]
    [InlineData("/%5Cevil.test")]
    [InlineData("/%5cevil.test")]
    [InlineData("/go?next=\\evil.test")]
    public void RejectsBackslash(string input)
    {
        Assert.Equal(Fallback, TelegramOidcEndpoints.SafeLocalReturnUrl(input, Fallback));
    }

    /// <summary>
    /// The 1.1.0 bypass: browsers drop tab/LF/CR from a Location header, so "/\t/evil.test" is
    /// followed as "//evil.test". ASP.NET Core query binding decodes "%09" once, which is why the raw
    /// characters are what reaches the check from a "?returnUrl=/%09/evil.test" request.
    /// </summary>
    [Theory]
    [InlineData("/\t/evil.test")]
    [InlineData("/\n/evil.test")]
    [InlineData("/\r/evil.test")]
    [InlineData("/\r\n/evil.test")]
    [InlineData("/\t\\evil.test")]
    [InlineData("/dashboard\t")]
    [InlineData("/\0/evil.test")]
    [InlineData("/\u001F/evil.test")]
    [InlineData("/\u007F/evil.test")]
    [InlineData("/\u0085/evil.test")]
    [InlineData("/\u009F/evil.test")]
    public void RejectsRawControlCharacters(string input)
    {
        Assert.Equal(Fallback, TelegramOidcEndpoints.SafeLocalReturnUrl(input, Fallback));
    }

    [Theory]
    [InlineData("/%09/evil.test")]
    [InlineData("/%0a/evil.test")]
    [InlineData("/%0A/evil.test")]
    [InlineData("/%0d/evil.test")]
    [InlineData("/%0D%0A/evil.test")]
    [InlineData("/%00/evil.test")]
    [InlineData("/%7F/evil.test")]
    [InlineData("/%C2%85/evil.test")]
    [InlineData("/dashboard?x=%0d%0aSet-Cookie:a=b")]
    public void RejectsPercentEncodedControlCharacters(string input)
    {
        Assert.Equal(Fallback, TelegramOidcEndpoints.SafeLocalReturnUrl(input, Fallback));
    }

    [Theory]
    [InlineData("/%2509/evil.test")]
    [InlineData("/%250a/evil.test")]
    [InlineData("/%250D/evil.test")]
    [InlineData("/%252Fevil.test")]
    [InlineData("/%255Cevil.test")]
    [InlineData("/%25252Fevil.test")]
    public void RejectsMultiplyEncodedForms(string input)
    {
        Assert.Equal(Fallback, TelegramOidcEndpoints.SafeLocalReturnUrl(input, Fallback));
    }

    [Fact]
    public void RejectsEncodingNestedBeyondTheDecodeLimit()
    {
        // Five layers of encoding around a harmless 'A': nothing dangerous inside, but no legitimate
        // caller encodes this deep, so the value is refused instead of being decoded indefinitely.
        Assert.Equal(Fallback, TelegramOidcEndpoints.SafeLocalReturnUrl("/a%2525252541", Fallback));
    }
}
