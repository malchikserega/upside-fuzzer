using System.Security.Claims;
using TeamFlow.Infrastructure.Services;

namespace TeamFlow.Api.Middleware;

// Alternate credential path alongside the primary JWT bearer scheme: a caller
// may present an `X-Api-Key` header instead of `Authorization: Bearer ...`.
// Runs AFTER app.UseAuthentication() and only acts as a fallback (a valid
// Bearer token always wins if both are somehow present on the same request) --
// when the header IS present, no JWT already authenticated the request, and
// the key resolves to a real, non-revoked (or stale-cached, see
// ApiKeyService's own comment -- vulnerability #32) key, this sets
// context.User directly with the same claim shape JwtTokenService issues, so
// every existing [Authorize]/CurrentUserId call site downstream works
// completely unchanged regardless of which credential type authenticated the
// request.
public class ApiKeyAuthMiddleware
{
    private readonly RequestDelegate _next;

    public ApiKeyAuthMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context, ApiKeyService apiKeys)
    {
        if (context.User.Identity?.IsAuthenticated != true &&
            context.Request.Headers.TryGetValue("X-Api-Key", out var rawKeyValues))
        {
            var rawKey = rawKeyValues.ToString();
            if (!string.IsNullOrWhiteSpace(rawKey))
            {
                var user = await apiKeys.ValidateAsync(rawKey);
                if (user is not null)
                {
                    var claims = new[]
                    {
                        new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                        new Claim(ClaimTypes.Email, user.Email),
                        new Claim(ClaimTypes.Role, user.Role.ToString()),
                        new Claim("org_id", user.OrganizationId.ToString()),
                    };
                    var identity = new ClaimsIdentity(claims, "ApiKey");
                    context.User = new ClaimsPrincipal(identity);
                }
            }
        }

        await _next(context);
    }
}
