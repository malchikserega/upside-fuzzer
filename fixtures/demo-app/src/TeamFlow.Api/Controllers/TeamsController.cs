using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using TeamFlow.Core.Dtos;
using TeamFlow.Infrastructure.Services;

namespace TeamFlow.Api.Controllers;

[ApiController]
[Route("api")]
[Authorize]
public class TeamsController : ControllerBase
{
    private readonly TeamService _teams;

    public TeamsController(TeamService teams)
    {
        _teams = teams;
    }

    [HttpPost("organizations/{id:int}/teams")]
    [ProducesResponseType(typeof(TeamDto), 201)]
    public async Task<IActionResult> Create(int id, CreateTeamRequest request)
    {
        if (!ModelState.IsValid)
        {
            return ValidationProblem(ModelState);
        }
        var team = await _teams.CreateAsync(id, request.Name);
        return Created($"/api/teams/{team.Id}", new TeamDto { Id = team.Id, OrganizationId = team.OrganizationId, Name = team.Name });
    }

    [HttpGet("teams/{id:int}")]
    [ProducesResponseType(typeof(TeamDto), 200)]
    public async Task<IActionResult> GetById(int id)
    {
        try
        {
            var team = await _teams.GetAsync(id);
            return Ok(new TeamDto { Id = team.Id, OrganizationId = team.OrganizationId, Name = team.Name });
        }
        catch (TeamNotFoundException)
        {
            return NotFound();
        }
    }

    [HttpGet("teams/{id:int}/members")]
    [ProducesResponseType(typeof(List<TeamMemberDto>), 200)]
    public async Task<IActionResult> ListMembers(int id)
    {
        var members = await _teams.ListMembersAsync(id);
        return Ok(members.Select(m => new TeamMemberDto { Id = m.Id, TeamId = m.TeamId, UserId = m.UserId, Role = m.Role.ToString() }));
    }

    // Vulnerability #24: see TeamService.AddMemberAsync's own comment.
    [HttpPost("teams/{id:int}/members")]
    [ProducesResponseType(typeof(TeamMemberDto), 201)]
    public async Task<IActionResult> AddMember(int id, AddMemberRequest request)
    {
        if (!ModelState.IsValid)
        {
            return ValidationProblem(ModelState);
        }
        try
        {
            var membership = await _teams.AddMemberAsync(id, request.UserId, request.Role);
            return Created($"/api/teams/{id}/members/{membership.Id}", new TeamMemberDto { Id = membership.Id, TeamId = membership.TeamId, UserId = membership.UserId, Role = membership.Role.ToString() });
        }
        catch (TeamNotFoundException)
        {
            return NotFound();
        }
    }

    // Vulnerability #25: see TeamService.UpdateMembershipRoleAsync's own comment.
    [HttpPut("teams/memberships/{membershipId:int}")]
    [ProducesResponseType(typeof(TeamMemberDto), 200)]
    public async Task<IActionResult> UpdateMembership(int membershipId, UpdateMembershipRequest request)
    {
        try
        {
            var membership = await _teams.UpdateMembershipRoleAsync(membershipId, request.Role);
            return Ok(new TeamMemberDto { Id = membership.Id, TeamId = membership.TeamId, UserId = membership.UserId, Role = membership.Role.ToString() });
        }
        catch (TeamNotFoundException)
        {
            return NotFound();
        }
    }
}
