using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using TeamFlow.Core.Dtos;
using TeamFlow.Core.Entities;
using TeamFlow.Infrastructure.Data;
using TeamFlow.Infrastructure.Services;

namespace TeamFlow.Api.Controllers;

[ApiController]
[Route("api/organizations")]
[Authorize]
public class OrganizationsController : ControllerBase
{
    private readonly TeamFlowDbContext _db;
    private readonly CreditsService _credits;

    public OrganizationsController(TeamFlowDbContext db, CreditsService credits)
    {
        _db = db;
        _credits = credits;
    }

    // Vulnerability #6 (BOLA): any authenticated user can read any organization's
    // details, including its credit balance, regardless of their own org_id claim.
    [HttpGet("{id:int}")]
    [ProducesResponseType(typeof(OrganizationDto), 200)]
    public async Task<IActionResult> GetById(int id)
    {
        var org = await _db.Organizations.FirstOrDefaultAsync(o => o.Id == id);
        if (org is null)
        {
            return NotFound();
        }
        return Ok(new OrganizationDto { Id = org.Id, Name = org.Name, CreditBalance = org.CreditBalance });
    }

    // Vulnerability #7 (BOLA): cross-tenant project listing -- no check that the
    // caller's own org_id claim matches {id}.
    [HttpGet("{id:int}/projects")]
    [ProducesResponseType(typeof(List<ProjectDto>), 200)]
    public async Task<IActionResult> ListProjects(int id)
    {
        var projects = await _db.Projects.Where(p => p.OrganizationId == id)
            .Select(p => new ProjectDto { Id = p.Id, OrganizationId = p.OrganizationId, Name = p.Name, Description = p.Description })
            .ToListAsync();
        return Ok(projects);
    }

    // Vulnerability #8 (differential auth bypass) lives in
    // TeamFlow.Api/Middleware/LegacyManagerOnlyGateMiddleware.cs, not here --
    // deliberately, this action overrides the controller's class-level [Authorize]
    // with [AllowAnonymous], since the (bypassable) path-based gate is meant to be
    // the ONLY thing standing between a fully unauthenticated caller and this
    // endpoint (a case-varied path skips authentication *and* the role check both).
    [HttpPost("{id:int}/projects")]
    [AllowAnonymous]
    [ProducesResponseType(typeof(ProjectDto), 201)]
    public async Task<IActionResult> CreateProject(int id, CreateProjectRequest request)
    {
        if (!ModelState.IsValid)
        {
            return ValidationProblem(ModelState);
        }
        var org = await _db.Organizations.FirstOrDefaultAsync(o => o.Id == id);
        if (org is null)
        {
            return NotFound();
        }
        var project = new Project { OrganizationId = id, Name = request.Name, Description = request.Description };
        _db.Projects.Add(project);
        await _db.SaveChangesAsync();
        return Created($"/api/projects/{project.Id}", new ProjectDto { Id = project.Id, OrganizationId = project.OrganizationId, Name = project.Name, Description = project.Description });
    }

    // Vulnerability #23 (race condition): see CreditsService.WithdrawAsync's own
    // doc comment for the check-then-act TOCTOU window.
    [HttpPost("{id:int}/credits/withdraw")]
    [ProducesResponseType(typeof(OrganizationDto), 200)]
    [ProducesResponseType(409)]
    public async Task<IActionResult> WithdrawCredits(int id, CreditsWithdrawRequest request)
    {
        if (!ModelState.IsValid)
        {
            return ValidationProblem(ModelState);
        }
        try
        {
            var balance = await _credits.WithdrawAsync(id, request.Amount);
            return Ok(new { balance });
        }
        catch (InsufficientCreditsException)
        {
            return Conflict("Insufficient credits.");
        }
        catch (KeyNotFoundException)
        {
            return NotFound();
        }
    }
}
