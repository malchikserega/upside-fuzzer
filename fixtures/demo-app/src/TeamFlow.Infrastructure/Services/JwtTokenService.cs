using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using TeamFlow.Core.Entities;

namespace TeamFlow.Infrastructure.Services;

public class JwtTokenService
{
    // Demo-only signing key -- deliberately checked in, matching the disposable,
    // zero-setup nature of every other target this project fuzzes locally. Never do
    // this in a real deployment.
    public const string DemoSigningKey = "teamflow-demo-signing-key-do-not-use-in-prod-2026";
    public const string Issuer = "TeamFlow.Demo";

    public string IssueToken(User user)
    {
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(ClaimTypes.Role, user.Role.ToString()),
            new Claim("org_id", user.OrganizationId.ToString()),
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(DemoSigningKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(
            issuer: Issuer,
            audience: Issuer,
            claims: claims,
            expires: DateTime.UtcNow.AddHours(12),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
