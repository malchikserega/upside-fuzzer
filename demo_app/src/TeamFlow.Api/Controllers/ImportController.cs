using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using TeamFlow.Infrastructure.Services;

namespace TeamFlow.Api.Controllers;

[ApiController]
[Route("api/import")]
[Authorize]
public class ImportController : ControllerBase
{
    private readonly LegacyImportService _legacyImport;

    public ImportController(LegacyImportService legacyImport)
    {
        _legacyImport = legacyImport;
    }

    // Vulnerability #22 (.NET deserialization gadget surface): see
    // LegacyImportService's own doc comment. The raw request body is read and
    // handed to Newtonsoft.Json directly -- deliberately NOT bound through ASP.NET
    // Core's normal (safe, System.Text.Json-based) model binder, since the whole
    // point is to demonstrate what happens when a legacy code path bypasses that.
    [HttpPost("legacy")]
    [Consumes("application/json")]
    [ProducesResponseType(201)]
    public async Task<IActionResult> Legacy([FromQuery] int organizationId)
    {
        using var reader = new StreamReader(Request.Body);
        var rawJson = await reader.ReadToEndAsync();
        try
        {
            var project = await _legacyImport.ImportAsync(organizationId, rawJson);
            return Created($"/api/projects/{project.Id}", new { project.Id, project.Name });
        }
        catch (Exception ex) when (ex is Newtonsoft.Json.JsonException or TypeLoadException)
        {
            // Deliberately re-thrown as a generic 500 rather than swallowed --
            // letting this propagate as an unhandled exception is what makes it
            // visible to void/go/crash.go's triage as a real, reproducible crash
            // (the point of this endpoint), not silently absorbed into a clean 400.
            throw;
        }
    }
}
