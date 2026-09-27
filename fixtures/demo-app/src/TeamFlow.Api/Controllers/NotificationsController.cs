using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using TeamFlow.Core.Dtos;
using TeamFlow.Infrastructure.Data;

namespace TeamFlow.Api.Controllers;

[ApiController]
[Route("api")]
[Authorize]
public class NotificationsController : ControllerBase
{
    private readonly TeamFlowDbContext _db;

    public NotificationsController(TeamFlowDbContext db)
    {
        _db = db;
    }

    // Vulnerability #31 (BOLA): no check that {userId} is the caller's own id --
    // any authenticated user can read any other user's notification feed.
    [HttpGet("users/{userId:int}/notifications")]
    [ProducesResponseType(typeof(List<NotificationDto>), 200)]
    public async Task<IActionResult> List(int userId)
    {
        var notifications = await _db.Notifications.Where(n => n.UserId == userId)
            .Select(n => new NotificationDto { Id = n.Id, UserId = n.UserId, Type = n.Type, Message = n.Message, Read = n.ReadAt != null })
            .ToListAsync();
        return Ok(notifications);
    }

    // Same gap as List above -- reachable regardless of who owns the notification.
    [HttpPost("notifications/{id:int}/read")]
    [ProducesResponseType(200)]
    public async Task<IActionResult> MarkRead(int id)
    {
        var notification = await _db.Notifications.FirstOrDefaultAsync(n => n.Id == id);
        if (notification is null)
        {
            return NotFound();
        }
        notification.ReadAt = DateTime.UtcNow;
        await _db.SaveChangesAsync();
        return Ok(new NotificationDto { Id = notification.Id, UserId = notification.UserId, Type = notification.Type, Message = notification.Message, Read = true });
    }
}
