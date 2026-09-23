using System.ComponentModel.DataAnnotations;
using TeamFlow.Core.Entities;

namespace TeamFlow.Core.Dtos;

// Vulnerability #1 (mass assignment): Role is bound directly from the client's JSON
// body. A real registration DTO should never accept a caller-supplied role -- the
// server should always force new accounts to Member. Nothing here stops a caller
// from posting {"role":"Admin"} and getting an admin account for free.
public class RegisterRequest
{
    [Required, EmailAddress, StringLength(120, MinimumLength = 5)]
    public string Email { get; set; } = "";

    [Required, StringLength(64, MinimumLength = 8)]
    public string Password { get; set; } = "";

    [Required, StringLength(60, MinimumLength = 1)]
    public string OrganizationName { get; set; } = "";

    // Deliberately present and deliberately trusted -- see class comment above.
    public UserRole Role { get; set; } = UserRole.Member;
}

public class LoginRequest
{
    [Required, EmailAddress]
    public string Email { get; set; } = "";

    [Required]
    public string Password { get; set; } = "";
}

public class LoginResponse
{
    public string Token { get; set; } = "";
    public int UserId { get; set; }
    public int OrganizationId { get; set; }
    public string Role { get; set; } = "";
}

// The schema-declared response shape for GET /api/users/me and /api/users/{id}
// (vulnerability #3: the controller declares this type via [ProducesResponseType]
// but actually serializes the full User entity, which carries PasswordHash and
// InternalNotes -- neither declared here, both leaking in the real response body).
public class UserPublicDto
{
    public int Id { get; set; }
    public string Email { get; set; } = "";
    public string Role { get; set; } = "";
    public int OrganizationId { get; set; }
}

// Vulnerability #5 (mass assignment): Role and OrganizationId are bound directly
// from the client's JSON body on an update -- lets any caller who can reach this
// endpoint promote themselves to Admin or hop into another tenant's organization.
public class UpdateUserRequest
{
    [StringLength(120, MinimumLength = 5)]
    public string? Email { get; set; }

    public UserRole? Role { get; set; }
    public int? OrganizationId { get; set; }
}
