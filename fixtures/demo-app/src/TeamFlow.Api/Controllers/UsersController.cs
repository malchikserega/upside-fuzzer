using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using TeamFlow.Core.Dtos;
using TeamFlow.Infrastructure.Data;

namespace TeamFlow.Api.Controllers;

[ApiController]
[Route("api/users")]
[Authorize]
public class UsersController : ControllerBase
{
    private readonly TeamFlowDbContext _db;

    public UsersController(TeamFlowDbContext db)
    {
        _db = db;
    }

    private int CurrentUserId => int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);

    // Vulnerability #3 (schema-conformance: undeclared sensitive field). The
    // declared response shape below (UserPublicDto: id/email/role/organizationId)
    // is what Swashbuckle documents in the OpenAPI spec grammarc reads -- but the
    // handler returns the full User entity, which also carries PasswordHash and
    // InternalNotes. Both leak in the real response body despite never appearing in
    // the schema void/go/schema_oracle.go compares against, which is exactly the
    // undeclared-field pattern that oracle exists to catch
    // (schema_undeclared_sensitive_field:passwordHash).
    [HttpGet("me")]
    [ProducesResponseType(typeof(UserPublicDto), 200)]
    public async Task<IActionResult> Me()
    {
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == CurrentUserId);
        if (user is null)
        {
            return NotFound();
        }
        return Ok(user); // <-- the bug: should be Ok(new UserPublicDto { ... })
    }

    // Vulnerability #4 (BOLA): any authenticated user, from any organization, can
    // fetch any other user's full profile by id -- no check that {id} belongs to
    // the caller's own organization, or is the caller at all.
    [HttpGet("{id:int}")]
    [ProducesResponseType(typeof(UserPublicDto), 200)]
    public async Task<IActionResult> GetById(int id)
    {
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == id);
        if (user is null)
        {
            return NotFound();
        }
        return Ok(new UserPublicDto { Id = user.Id, Email = user.Email, Role = user.Role.ToString(), OrganizationId = user.OrganizationId });
    }

    // Vulnerability #5 (BOLA + mass assignment): no check that {id} == the caller's
    // own id, AND Role/OrganizationId are bound straight from the request body --
    // any authenticated user can promote any other user to Admin, or move them (or
    // themselves) into a different organization entirely.
    [HttpPut("{id:int}")]
    [ProducesResponseType(typeof(UserPublicDto), 200)]
    public async Task<IActionResult> Update(int id, UpdateUserRequest request)
    {
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == id);
        if (user is null)
        {
            return NotFound();
        }
        if (!string.IsNullOrWhiteSpace(request.Email))
        {
            user.Email = request.Email;
        }
        if (request.Role.HasValue)
        {
            user.Role = request.Role.Value; // <-- the bug
        }
        if (request.OrganizationId.HasValue)
        {
            user.OrganizationId = request.OrganizationId.Value; // <-- the bug
        }
        await _db.SaveChangesAsync();
        return Ok(new UserPublicDto { Id = user.Id, Email = user.Email, Role = user.Role.ToString(), OrganizationId = user.OrganizationId });
    }
}
