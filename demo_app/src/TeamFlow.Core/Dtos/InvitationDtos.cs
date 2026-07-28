using System.ComponentModel.DataAnnotations;
using TeamFlow.Core.Entities;

namespace TeamFlow.Core.Dtos;

public class InvitationDto
{
    public int Id { get; set; }
    public int OrganizationId { get; set; }
    public string Email { get; set; } = "";
    public string Token { get; set; } = "";
    public string Role { get; set; } = "";
    public string Status { get; set; } = "";
}

public class CreateInvitationRequest
{
    [Required, EmailAddress]
    public string Email { get; set; } = "";

    public UserRole Role { get; set; } = UserRole.Member;
}

// Vulnerability #27 (sequence-only, BOLA+privilege-escalation): lets the caller
// change a still-Pending invitation's Role before it's accepted -- see
// InvitationService.UpdateRoleAsync's own comment for why this only manifests
// through a 3-step chain (invite -> update role -> accept).
public class UpdateInvitationRequest
{
    [Required]
    public UserRole Role { get; set; }
}

public class AcceptInvitationRequest
{
    [Required, StringLength(64, MinimumLength = 8)]
    public string Password { get; set; } = "";
}
