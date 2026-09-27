using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using TeamFlow.Core.Dtos;
using TeamFlow.Core.Entities;
using TeamFlow.Infrastructure.Data;

namespace TeamFlow.Api.Controllers;

[ApiController]
[Route("api")]
[Authorize]
public class CommentsController : ControllerBase
{
    private readonly TeamFlowDbContext _db;

    public CommentsController(TeamFlowDbContext db)
    {
        _db = db;
    }

    private int CurrentUserId => int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);

    [HttpGet("tasks/{taskId:int}/comments")]
    [ProducesResponseType(typeof(List<CommentDto>), 200)]
    public async Task<IActionResult> List(int taskId)
    {
        var comments = await _db.Comments.Where(c => c.TaskId == taskId)
            .Select(c => new CommentDto { Id = c.Id, TaskId = c.TaskId, AuthorUserId = c.AuthorUserId, Body = c.Body })
            .ToListAsync();
        return Ok(comments);
    }

    // Vulnerability #29 (mass assignment): AuthorUserId is trusted straight from
    // the request body when present -- a caller can post a comment attributed to
    // any other user id, not just themselves.
    [HttpPost("tasks/{taskId:int}/comments")]
    [ProducesResponseType(typeof(CommentDto), 201)]
    public async Task<IActionResult> Create(int taskId, CreateCommentRequest request)
    {
        if (!ModelState.IsValid)
        {
            return ValidationProblem(ModelState);
        }
        var comment = new Comment
        {
            TaskId = taskId,
            AuthorUserId = request.AuthorUserId ?? CurrentUserId, // <-- the bug: request.AuthorUserId wins when present
            Body = request.Body,
        };
        _db.Comments.Add(comment);
        await _db.SaveChangesAsync();
        return Created($"/api/comments/{comment.Id}", new CommentDto { Id = comment.Id, TaskId = comment.TaskId, AuthorUserId = comment.AuthorUserId, Body = comment.Body });
    }

    // Vulnerability #30 (BOLA): no check that the caller is the comment's own
    // AuthorUserId (or shares an organization with it) before allowing an edit.
    [HttpPut("comments/{id:int}")]
    [ProducesResponseType(typeof(CommentDto), 200)]
    public async Task<IActionResult> Update(int id, UpdateCommentRequest request)
    {
        if (!ModelState.IsValid)
        {
            return ValidationProblem(ModelState);
        }
        var comment = await _db.Comments.FirstOrDefaultAsync(c => c.Id == id);
        if (comment is null)
        {
            return NotFound();
        }
        comment.Body = request.Body; // <-- the bug: any authenticated caller reaches this line
        await _db.SaveChangesAsync();
        return Ok(new CommentDto { Id = comment.Id, TaskId = comment.TaskId, AuthorUserId = comment.AuthorUserId, Body = comment.Body });
    }

    // Vulnerability #30 (BOLA), delete side of the same gap as Update above.
    [HttpDelete("comments/{id:int}")]
    [ProducesResponseType(204)]
    public async Task<IActionResult> Delete(int id)
    {
        var comment = await _db.Comments.FirstOrDefaultAsync(c => c.Id == id);
        if (comment is null)
        {
            return NotFound();
        }
        _db.Comments.Remove(comment);
        await _db.SaveChangesAsync();
        return NoContent();
    }
}
