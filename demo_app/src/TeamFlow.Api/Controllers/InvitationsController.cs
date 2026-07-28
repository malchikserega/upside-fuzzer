using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using TeamFlow.Core.Dtos;
using TeamFlow.Infrastructure.Services;

namespace TeamFlow.Api.Controllers;

[ApiController]
[Route("api")]
public class InvitationsController : ControllerBase
{
    private readonly InvitationService _invitations;

    public InvitationsController(InvitationService invitations)
    {
        _invitations = invitations;
    }

    private int CurrentUserId => int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);

    [HttpPost("organizations/{id:int}/invitations")]
    [Authorize]
    [ProducesResponseType(typeof(InvitationDto), 201)]
    public async Task<IActionResult> Create(int id, CreateInvitationRequest request)
    {
        if (!ModelState.IsValid)
        {
            return ValidationProblem(ModelState);
        }
        var invitation = await _invitations.CreateAsync(id, CurrentUserId, request.Email, request.Role);
        return Created($"/api/invitations/{invitation.Id}", new InvitationDto
        {
            Id = invitation.Id,
            OrganizationId = invitation.OrganizationId,
            Email = invitation.Email,
            Token = invitation.Token,
            Role = invitation.Role.ToString(),
            Status = invitation.Status.ToString(),
        });
    }

    [HttpGet("invitations/{token}")]
    [ProducesResponseType(typeof(InvitationDto), 200)]
    public async Task<IActionResult> GetByToken(string token)
    {
        try
        {
            var invitation = await _invitations.GetByTokenAsync(token);
            return Ok(new InvitationDto
            {
                Id = invitation.Id,
                OrganizationId = invitation.OrganizationId,
                Email = invitation.Email,
                Token = invitation.Token,
                Role = invitation.Role.ToString(),
                Status = invitation.Status.ToString(),
            });
        }
        catch (InvitationNotFoundException)
        {
            return NotFound();
        }
    }

    // Vulnerability #27 (sequence-only): see InvitationService.UpdateRoleAsync's
    // own comment.
    [HttpPut("invitations/{id:int}")]
    [Authorize]
    [ProducesResponseType(typeof(InvitationDto), 200)]
    public async Task<IActionResult> UpdateRole(int id, UpdateInvitationRequest request)
    {
        try
        {
            var invitation = await _invitations.UpdateRoleAsync(id, request.Role);
            return Ok(new InvitationDto
            {
                Id = invitation.Id,
                OrganizationId = invitation.OrganizationId,
                Email = invitation.Email,
                Token = invitation.Token,
                Role = invitation.Role.ToString(),
                Status = invitation.Status.ToString(),
            });
        }
        catch (InvitationNotFoundException)
        {
            return NotFound();
        }
        catch (InvitationNotPendingException)
        {
            return Conflict("Invitation is no longer pending.");
        }
    }

    [HttpPost("invitations/{id:int}/revoke")]
    [Authorize]
    [ProducesResponseType(204)]
    public async Task<IActionResult> Revoke(int id)
    {
        try
        {
            await _invitations.RevokeAsync(id);
            return NoContent();
        }
        catch (InvitationNotFoundException)
        {
            return NotFound();
        }
    }

    // Vulnerabilities #26 (BOLA) + #28 (sequence-only race): see
    // InvitationService.AcceptAsync's own comment. Deliberately [AllowAnonymous]
    // -- accepting an invitation is how a brand-new user gets their first
    // account and token, so there is no existing session to authenticate with
    // yet on the happy path either.
    [HttpPost("invitations/{token}/accept")]
    [AllowAnonymous]
    [ProducesResponseType(typeof(LoginResponse), 201)]
    public async Task<IActionResult> Accept(string token, AcceptInvitationRequest request)
    {
        if (!ModelState.IsValid)
        {
            return ValidationProblem(ModelState);
        }
        try
        {
            var user = await _invitations.AcceptAsync(token, request.Password);
            return Created($"/api/users/{user.Id}", new LoginResponse
            {
                Token = _invitations.IssueToken(user),
                UserId = user.Id,
                OrganizationId = user.OrganizationId,
                Role = user.Role.ToString(),
            });
        }
        catch (InvitationNotFoundException)
        {
            return NotFound();
        }
        catch (InvitationNotPendingException)
        {
            return Conflict("Invitation is no longer pending.");
        }
    }
}
