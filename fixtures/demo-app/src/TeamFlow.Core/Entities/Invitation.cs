namespace TeamFlow.Core.Entities;

public class Invitation
{
    public int Id { get; set; }
    public int OrganizationId { get; set; }
    public string Email { get; set; } = "";
    public string Token { get; set; } = "";
    public UserRole Role { get; set; } = UserRole.Member;
    public InvitationStatus Status { get; set; } = InvitationStatus.Pending;
    public int InvitedByUserId { get; set; }
    public int? AcceptedUserId { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
