using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Telegram.OpenIdConnect.AspNetCore;

/// <summary>Maps the HTTP endpoints Telegram OpenID Connect sign-in needs.</summary>
public static class TelegramOidcEndpoints
{
    /// <summary>
    /// Maps the challenge (GET {CallbackPath}/challenge) and logout (POST {CallbackPath}/logout)
    /// endpoints. Challenge kicks off the OIDC redirect; logout is a local cookie sign-out with
    /// manual antiforgery validation.
    /// </summary>
    public static IEndpointRouteBuilder MapTelegramOidcEndpoints(this IEndpointRouteBuilder endpoints)
    {
        TelegramOidcOptions options = endpoints.ServiceProvider.GetRequiredService<TelegramOidcOptions>();
        string basePath = options.CallbackPath.TrimEnd('/');

        if (string.IsNullOrWhiteSpace(options.ClientId))
        {
            ILogger startupLogger = endpoints.ServiceProvider.GetRequiredService<ILoggerFactory>().CreateLogger("TelegramOidc");
            startupLogger.LogWarning(
                "Telegram OIDC is not configured; sign-in will be unreachable until TelegramOidc:ClientId/ClientSecret are set.");
        }

        endpoints.MapGet(basePath + "/challenge", (HttpContext http, IOptionsMonitor<OpenIdConnectOptions> oidcMonitor, string? returnUrl) =>
        {
            OpenIdConnectOptions oidcOptions = oidcMonitor.Get(options.OidcScheme);
            bool clientIdMissing = string.IsNullOrWhiteSpace(oidcOptions.ClientId) ||
                string.Equals(oidcOptions.ClientId, TelegramOidcExtensions.UnconfiguredClientId, StringComparison.Ordinal);
            bool clientSecretMissing = string.IsNullOrWhiteSpace(oidcOptions.ClientSecret) ||
                string.Equals(oidcOptions.ClientSecret, TelegramOidcExtensions.UnconfiguredClientSecret, StringComparison.Ordinal);
            if (clientIdMissing || clientSecretMissing)
            {
                ILogger logger = http.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("TelegramOidc");
                logger.LogWarning(
                    "Telegram OIDC sign-in attempted but not configured (ClientId missing: {ClientIdMissing}, ClientSecret missing: {ClientSecretMissing}).",
                    clientIdMissing, clientSecretMissing);
                return Results.Text("Telegram OIDC sign-in is not configured.", statusCode: StatusCodes.Status503ServiceUnavailable);
            }

            string target = SafeLocalReturnUrl(returnUrl, options.DefaultReturnUrl);
            return Results.Challenge(new AuthenticationProperties { RedirectUri = target }, [options.OidcScheme]);
        });

        endpoints.MapPost(basePath + "/logout", async (HttpContext http, IAntiforgery antiforgery) =>
        {
            try
            {
                await antiforgery.ValidateRequestAsync(http).ConfigureAwait(false);
            }
            catch (AntiforgeryValidationException)
            {
                return Results.BadRequest("Invalid antiforgery token.");
            }

            await http.SignOutAsync(options.CookieScheme).ConfigureAwait(false);
            return Results.Redirect(options.LoginPath);
        });

        return endpoints;
    }

    /// <summary>Returns returnUrl only if it is a local path (leading single '/'); otherwise fallback.</summary>
    internal static string SafeLocalReturnUrl(string? returnUrl, string fallback)
    {
        if (string.IsNullOrEmpty(returnUrl))
        {
            return fallback;
        }

        // Local means: starts with '/', but not '//' or '/\' (protocol-relative / backslash tricks).
        if (returnUrl[0] == '/' && (returnUrl.Length == 1 || (returnUrl[1] != '/' && returnUrl[1] != '\\')))
        {
            return returnUrl;
        }

        return fallback;
    }
}
