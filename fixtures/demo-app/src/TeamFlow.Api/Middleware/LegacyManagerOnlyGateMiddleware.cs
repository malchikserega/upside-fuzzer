using System.Security.Claims;

namespace TeamFlow.Api.Middleware;

// Vulnerability #8 (differential auth bypass), the flagship "case confusion" demo.
//
// "Create a project" is gated to Manager/Admin only. Every OTHER role-restricted
// endpoint in this API uses standard [Authorize(Roles = "...")] attributes, which
// ASP.NET's routing resolves case-INsensitively (routing itself doesn't care about
// path casing -- "/API/Organizations/5/Projects" and "/api/organizations/5/projects"
// both route to the exact same controller action). This one endpoint is different:
// it predates the [Authorize]-based model and still uses a hand-rolled gate ported
// from an old API-gateway config that matched on the raw request path -- and that
// gate does an exact, case-SENSITIVE comparison.
//
// The bug: a request path cased differently than "/api/organizations/{id}/projects"
// still resolves to the same controller action (routing doesn't care about case) but
// silently skips THIS gate entirely, because the case-sensitive StartsWith below
// simply doesn't match. The controller action itself carries no [Authorize] of its
// own, so once this gate is bypassed, nothing else stands in the way.
//
// void/go/oracle.go's differential/parser-confusion probes test exactly this: they
// only fire on endpoints that already showed STRONG evidence of enforcing auth (a
// normal-cased, credential-free request got a real 401/403 here first), then replay
// the identical request with one of several confusion techniques -- including
// route-case variants -- to see if any of them slip past. This gate produces a real
// 401/403 for the normal case and a real bypass for the varied case, which is
// exactly the shape that oracle is built to catch (differential_auth_bypass:route-case).
public class LegacyManagerOnlyGateMiddleware
{
    private readonly RequestDelegate _next;

    public LegacyManagerOnlyGateMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path.Value ?? "";
        var method = context.Request.Method;

        var isCreateProjectPath =
            method == "POST" &&
            path.StartsWith("/api/organizations/", StringComparison.Ordinal) && // <-- the bug: Ordinal, not OrdinalIgnoreCase
            path.EndsWith("/projects", StringComparison.Ordinal);

        if (isCreateProjectPath)
        {
            if (context.User.Identity?.IsAuthenticated != true)
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return;
            }
            var role = context.User.FindFirst(ClaimTypes.Role)?.Value;
            if (role != "Manager" && role != "Admin")
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return;
            }
        }

        await _next(context);
    }
}
