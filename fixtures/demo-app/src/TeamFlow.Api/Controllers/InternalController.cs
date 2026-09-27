using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace TeamFlow.Api.Controllers;

// Not itself a vulnerability -- a local stand-in for a real cloud metadata service,
// used to verify vulnerability #19 (SSRF) without needing a real cloud VM. See
// README.md's "Verifying SSRF locally" section. Deliberately unauthenticated and
// shaped like AWS's real IMDS response, since that's what void/go/identity.go's
// exploitationSignals SSRF markers (accesskeyid/secretaccesskey/sessiontoken/...)
// are written to recognize.
[ApiController]
[Route("api/internal/aws-metadata-stub")]
[AllowAnonymous]
public class InternalController : ControllerBase
{
    [HttpGet("latest/meta-data/iam/security-credentials/demo-role")]
    public IActionResult FakeCredentials()
    {
        return Content(
            """
            {
              "Code": "Success",
              "AccessKeyId": "AKIADEMOFAKEACCESSKEY",
              "SecretAccessKey": "demo/fake+secret+access+key+not+real",
              "Token": "demo-fake-session-token-not-real",
              "Expiration": "2099-01-01T00:00:00Z"
            }
            """,
            "application/json");
    }
}
