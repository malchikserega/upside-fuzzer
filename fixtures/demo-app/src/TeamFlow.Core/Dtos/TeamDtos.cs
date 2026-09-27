using System.ComponentModel.DataAnnotations;

namespace TeamFlow.Core.Dtos;

public class TeamDto
{
    public int Id { get; set; }
    public int OrganizationId { get; set; }
    public string Name { get; set; } = "";
}

public class CreateTeamRequest
{
    [Required, StringLength(80, MinimumLength = 2)]
    public string Name { get; set; } = "";
}

public class TeamMemberDto
{
    public int Id { get; set; }
    public int TeamId { get; set; }
    public int UserId { get; set; }
    public string Role { get; set; } = "";
}

// Vulnerability #24 (BOLA + missing self-role-check): AddMemberRequest lets the
// caller specify an arbitrary UserId (no check it belongs to the same
// organization as the team) AND an arbitrary Role (no check the caller
// themselves holds Lead on this team before granting Lead to someone else --
// see TeamService.AddMemberAsync's own comment).
public class AddMemberRequest
{
    [Required]
    public int UserId { get; set; }

    public Entities.TeamRole Role { get; set; } = Entities.TeamRole.Member;
}

public class UpdateMembershipRequest
{
    public Entities.TeamRole Role { get; set; }
}
