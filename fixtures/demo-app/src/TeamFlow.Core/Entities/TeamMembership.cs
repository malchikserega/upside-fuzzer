namespace TeamFlow.Core.Entities;

public class TeamMembership
{
    public int Id { get; set; }
    public int TeamId { get; set; }
    public int UserId { get; set; }
    public TeamRole Role { get; set; } = TeamRole.Member;
}
