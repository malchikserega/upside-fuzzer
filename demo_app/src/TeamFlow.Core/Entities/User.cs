namespace TeamFlow.Core.Entities;

public class User
{
    public int Id { get; set; }
    public int OrganizationId { get; set; }
    public string Email { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    public UserRole Role { get; set; } = UserRole.Member;
    public bool IsActive { get; set; } = true;

    // Internal-only field, never meant to leave the server -- the response-schema
    // conformance demo (#3 in the catalog) relies on this leaking by accident.
    public string? InternalNotes { get; set; }
}
