using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using TeamFlow.Core.Dtos;
using TeamFlow.Core.Entities;
using TeamFlow.Infrastructure.Data;
using TeamFlow.Infrastructure.Services;

namespace TeamFlow.Api.Controllers;

[ApiController]
[Route("api/projects")]
[Authorize]
public class ProjectsController : ControllerBase
{
    private readonly TeamFlowDbContext _db;
    private readonly TaskSearchService _search;

    public ProjectsController(TeamFlowDbContext db, TaskSearchService search)
    {
        _db = db;
        _search = search;
    }

    // Vulnerability #9 (BOLA): any authenticated user can read any project's
    // details, regardless of which organization they belong to.
    [HttpGet("{id:int}")]
    [ProducesResponseType(typeof(ProjectDto), 200)]
    public async Task<IActionResult> GetById(int id)
    {
        var project = await _db.Projects.FirstOrDefaultAsync(p => p.Id == id);
        if (project is null)
        {
            return NotFound();
        }
        return Ok(new ProjectDto { Id = project.Id, OrganizationId = project.OrganizationId, Name = project.Name, Description = project.Description });
    }

    // Vulnerability #10 (SQL injection): the optional ?search= is passed straight
    // into TaskSearchService's raw, string-concatenated query when present. Without
    // ?search=, this falls back to the safe EF Core path -- the vulnerability only
    // exists on the search branch, mirroring how real SQLi usually hides behind one
    // specific "advanced" feature rather than the whole endpoint.
    [HttpGet("{id:int}/tasks")]
    [ProducesResponseType(typeof(List<TaskDto>), 200)]
    public async Task<IActionResult> ListTasks(int id, [FromQuery] string? search)
    {
        if (!string.IsNullOrEmpty(search))
        {
            var rows = _search.Search(id, search); // <-- the bug
            return Ok(rows.Select(r => new TaskDto { Id = r.Id, ProjectId = id, Title = r.Title }));
        }

        var tasks = await _db.ProjectTasks.Where(t => t.ProjectId == id)
            .Select(t => new TaskDto { Id = t.Id, ProjectId = t.ProjectId, Title = t.Title, Description = t.Description, Status = t.Status.ToString(), AssignedUserId = t.AssignedUserId })
            .ToListAsync();
        return Ok(tasks);
    }

    // Vulnerability #11 is deliberately absent here -- this endpoint exists purely
    // to give Top-20 #14's constraint-aware boundary mutation real declared bounds
    // (CreateTaskRequest's [StringLength]/[Range]) to fuzz against.
    [HttpPost("{id:int}/tasks")]
    [ProducesResponseType(typeof(TaskDto), 201)]
    public async Task<IActionResult> CreateTask(int id, CreateTaskRequest request)
    {
        if (!ModelState.IsValid)
        {
            return ValidationProblem(ModelState);
        }
        var project = await _db.Projects.FirstOrDefaultAsync(p => p.Id == id);
        if (project is null)
        {
            return NotFound();
        }
        var task = new ProjectTask { ProjectId = id, Title = request.Title, Description = request.Description, AssignedUserId = request.AssignedUserId };
        _db.ProjectTasks.Add(task);
        await _db.SaveChangesAsync();
        return Created($"/api/tasks/{task.Id}", new TaskDto { Id = task.Id, ProjectId = task.ProjectId, Title = task.Title, Description = task.Description, Status = task.Status.ToString(), AssignedUserId = task.AssignedUserId });
    }

    // Baseline planted crash (mirrors fixtures/planted-bug-api's own bug): no
    // bounds check on bucketSize before it's used as a divisor. bucketSize=0
    // throws DivideByZeroException deterministically, with no sequencing required
    // -- the simplest, fastest-to-find case in this demo, included deliberately
    // alongside the more elaborate ones.
    [HttpGet("{id:int}/tasks/stats")]
    [ProducesResponseType(200)]
    public async Task<IActionResult> TaskStats(int id, [FromQuery] int bucketSize = 5)
    {
        var count = await _db.ProjectTasks.CountAsync(t => t.ProjectId == id);
        var buckets = count / bucketSize; // <-- the bug: bucketSize=0 throws
        return Ok(new { totalTasks = count, bucketSize, buckets });
    }
}
