using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using TeamFlow.Core.Dtos;
using TeamFlow.Infrastructure.Data;
using TeamFlow.Infrastructure.Services;

namespace TeamFlow.Api.Controllers;

[ApiController]
[Route("api/tasks")]
[Authorize]
public class TasksController : ControllerBase
{
    private readonly TeamFlowDbContext _db;
    private readonly TaskLifecycleService _lifecycle;
    private readonly TaskPreviewService _preview;

    public TasksController(TeamFlowDbContext db, TaskLifecycleService lifecycle, TaskPreviewService preview)
    {
        _db = db;
        _lifecycle = lifecycle;
        _preview = preview;
    }

    // Vulnerability #12 (BOLA): any authenticated user can read any task, in any
    // project, in any organization.
    [HttpGet("{id:int}")]
    [ProducesResponseType(typeof(TaskDto), 200)]
    public async Task<IActionResult> GetById(int id)
    {
        var task = await _db.ProjectTasks.FirstOrDefaultAsync(t => t.Id == id);
        if (task is null)
        {
            return NotFound();
        }
        return Ok(new TaskDto { Id = task.Id, ProjectId = task.ProjectId, Title = task.Title, Description = task.Description, Status = task.Status.ToString(), AssignedUserId = task.AssignedUserId });
    }

    // Deliberately clean: drives the task into whatever state a sequence needs
    // (including Archived -- see vulnerability #16 below, and Todo/InProgress for
    // #21's unlock precondition).
    [HttpPut("{id:int}")]
    [ProducesResponseType(typeof(TaskDto), 200)]
    public async Task<IActionResult> Update(int id, UpdateTaskRequest request)
    {
        if (!ModelState.IsValid)
        {
            return ValidationProblem(ModelState);
        }
        var task = await _db.ProjectTasks.FirstOrDefaultAsync(t => t.Id == id);
        if (task is null)
        {
            return NotFound();
        }
        if (!string.IsNullOrWhiteSpace(request.Title))
        {
            task.Title = request.Title;
        }
        if (request.Description is not null)
        {
            task.Description = request.Description;
        }
        if (request.Status.HasValue)
        {
            task.Status = request.Status.Value;
            if (task.Status == Core.Entities.ProjectTaskStatus.Archived)
            {
                task.ArchivedAt = DateTime.UtcNow; // note: does NOT populate archive metadata -- see #16
            }
        }
        if (request.AssignedUserId.HasValue)
        {
            task.AssignedUserId = request.AssignedUserId;
        }
        await _db.SaveChangesAsync();
        return Ok(new TaskDto { Id = task.Id, ProjectId = task.ProjectId, Title = task.Title, Description = task.Description, Status = task.Status.ToString(), AssignedUserId = task.AssignedUserId });
    }

    // Vulnerability #14 (broken authentication): [AllowAnonymous] where every other
    // write endpoint in this controller requires [Authorize] -- a copy-paste-from-a-
    // read-endpoint mistake, the single most common real cause of this bug class.
    // Any caller, with no credentials at all, can delete any task.
    [HttpDelete("{id:int}")]
    [AllowAnonymous]
    [ProducesResponseType(204)]
    public async Task<IActionResult> Delete(int id)
    {
        var task = await _db.ProjectTasks.FirstOrDefaultAsync(t => t.Id == id);
        if (task is null)
        {
            return NotFound();
        }
        _db.ProjectTasks.Remove(task);
        await _db.SaveChangesAsync();
        return NoContent();
    }

    // Vulnerability #15 (SSTI + reflected XSS): see TaskPreviewService.RenderAsync's
    // own doc comment.
    [HttpGet("{id:int}/preview")]
    [ProducesResponseType(200)]
    public async Task<IActionResult> Preview(int id, [FromQuery] string format = "text")
    {
        try
        {
            var rendered = await _preview.RenderAsync(id, format);
            if (string.Equals(format, "html", StringComparison.OrdinalIgnoreCase))
            {
                return Content(rendered, "text/html");
            }
            return Content(rendered, "text/plain");
        }
        catch (TaskNotFoundException)
        {
            return NotFound();
        }
    }

    // Vulnerability #16 (stateful, coverage-guided-only): see
    // TaskLifecycleService.RestoreAsync's own doc comment.
    [HttpPost("{taskId:int}/restore")]
    [ProducesResponseType(200)]
    public async Task<IActionResult> Restore(int taskId)
    {
        try
        {
            await _lifecycle.RestoreAsync(taskId);
            return Ok(new { restored = true });
        }
        catch (TaskNotFoundException)
        {
            return NotFound();
        }
    }

    // Vulnerability #21 (nested-branch gate, coverage-guided-only): see
    // TaskLifecycleService.TryUnlockAsync's own doc comment.
    [HttpPost("{taskId:int}/unlock")]
    [ProducesResponseType(200)]
    public async Task<IActionResult> Unlock(int taskId, UnlockRequest request)
    {
        try
        {
            var unlocked = await _lifecycle.TryUnlockAsync(taskId, request.VerificationLevel, request.Region, request.UnlockCode);
            return Ok(new { unlocked });
        }
        catch (TaskNotFoundException)
        {
            return NotFound();
        }
    }
}
