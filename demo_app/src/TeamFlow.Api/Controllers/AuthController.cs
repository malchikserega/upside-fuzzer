using Microsoft.AspNetCore.Mvc;
using TeamFlow.Core.Dtos;
using TeamFlow.Infrastructure.Services;

namespace TeamFlow.Api.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly AuthService _auth;

    public AuthController(AuthService auth)
    {
        _auth = auth;
    }

    // Vulnerability #1: see RegisterRequest.Role's own doc comment (TeamFlow.Core).
    [HttpPost("register")]
    [ProducesResponseType(typeof(LoginResponse), 201)]
    public async Task<ActionResult<LoginResponse>> Register(RegisterRequest request)
    {
        if (!ModelState.IsValid)
        {
            return ValidationProblem(ModelState);
        }
        var (user, org) = await _auth.RegisterAsync(request);
        var token = _auth.IssueToken(user);
        return Created($"/api/users/{user.Id}", new LoginResponse
        {
            Token = token,
            UserId = user.Id,
            OrganizationId = org.Id,
            Role = user.Role.ToString(),
        });
    }

    [HttpPost("login")]
    [ProducesResponseType(typeof(LoginResponse), 200)]
    [ProducesResponseType(401)]
    public async Task<ActionResult<LoginResponse>> Login(LoginRequest request)
    {
        if (!ModelState.IsValid)
        {
            return ValidationProblem(ModelState);
        }
        var user = await _auth.ValidateCredentialsAsync(request.Email, request.Password);
        if (user is null)
        {
            return Unauthorized();
        }
        return Ok(new LoginResponse
        {
            Token = _auth.IssueToken(user),
            UserId = user.Id,
            OrganizationId = user.OrganizationId,
            Role = user.Role.ToString(),
        });
    }
}
