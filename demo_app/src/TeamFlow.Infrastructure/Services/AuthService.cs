using Microsoft.EntityFrameworkCore;
using TeamFlow.Core.Dtos;
using TeamFlow.Core.Entities;
using TeamFlow.Infrastructure.Data;

namespace TeamFlow.Infrastructure.Services;

public class AuthService
{
    private readonly TeamFlowDbContext _db;
    private readonly JwtTokenService _jwt;

    public AuthService(TeamFlowDbContext db, JwtTokenService jwt)
    {
        _db = db;
        _jwt = jwt;
    }

    // Vulnerability #1 (mass assignment): request.Role is trusted verbatim. A real
    // registration flow must always force Role = Member server-side, regardless of
    // what the client posts.
    public async Task<(User user, Organization org)> RegisterAsync(RegisterRequest request)
    {
        var org = new Core.Entities.Organization { Name = request.OrganizationName };
        _db.Organizations.Add(org);
        await _db.SaveChangesAsync();

        var user = new User
        {
            OrganizationId = org.Id,
            Email = request.Email,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password),
            Role = request.Role, // <-- the bug: should always be UserRole.Member
        };
        _db.Users.Add(user);
        await _db.SaveChangesAsync();

        return (user, org);
    }

    public async Task<User?> ValidateCredentialsAsync(string email, string password)
    {
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == email && u.IsActive);
        if (user is null)
        {
            return null;
        }
        return BCrypt.Net.BCrypt.Verify(password, user.PasswordHash) ? user : null;
    }

    public string IssueToken(User user) => _jwt.IssueToken(user);
}
