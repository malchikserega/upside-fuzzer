using Microsoft.EntityFrameworkCore;
using TeamFlow.Core.Entities;
using TeamFlow.Infrastructure.Data;

namespace TeamFlow.Infrastructure.Services;

public class TeamNotFoundException : Exception
{
}

public class TeamService
{
    private readonly TeamFlowDbContext _db;

    public TeamService(TeamFlowDbContext db)
    {
        _db = db;
    }

    public async Task<Team> CreateAsync(int organizationId, string name)
    {
        var team = new Team { OrganizationId = organizationId, Name = name };
        _db.Teams.Add(team);
        await _db.SaveChangesAsync();
        return team;
    }

    public async Task<Team> GetAsync(int teamId)
    {
        return await _db.Teams.FirstOrDefaultAsync(t => t.Id == teamId)
            ?? throw new TeamNotFoundException();
    }

    public async Task<List<TeamMembership>> ListMembersAsync(int teamId)
    {
        return await _db.TeamMemberships.Where(m => m.TeamId == teamId).ToListAsync();
    }

    // Vulnerability #24 (BOLA + missing self-role-check): two independent gaps in
    // one method. (1) userId is trusted with no check that the target user
    // belongs to the same organization as the team -- any user id from any
    // tenant can be added to any team. (2) role is trusted with no check that
    // the CALLER themselves currently holds Lead on this team -- an ordinary
    // Member of the team (or of no team at all) can add someone as Lead,
    // including granting Lead to themselves via their own UserId. A correct
    // implementation would look up the caller's own TeamMembership first and
    // reject Role=Lead unless the caller is already a Lead.
    public async Task<TeamMembership> AddMemberAsync(int teamId, int userId, TeamRole role)
    {
        var team = await GetAsync(teamId);
        var membership = new TeamMembership { TeamId = team.Id, UserId = userId, Role = role };
        _db.TeamMemberships.Add(membership);
        await _db.SaveChangesAsync();
        return membership;
    }

    // Vulnerability #25 (self-role-escalation): identical gap as #24's role check,
    // but reached through the update path instead of the add path -- a Member's
    // own membership row can be PUT to Role=Lead with no check of the caller's
    // current role at all (the caller isn't even compared against the
    // membership's UserId).
    public async Task<TeamMembership> UpdateMembershipRoleAsync(int membershipId, TeamRole role)
    {
        var membership = await _db.TeamMemberships.FirstOrDefaultAsync(m => m.Id == membershipId)
            ?? throw new TeamNotFoundException();
        membership.Role = role;
        await _db.SaveChangesAsync();
        return membership;
    }
}
