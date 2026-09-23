using Microsoft.AspNetCore.Mvc;
using TeamFlow.Core.Dtos;
using TeamFlow.Infrastructure.Services;

namespace TeamFlow.Api.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly AuthService _auth;
    private readonly PasswordResetService _resets;

    public AuthController(AuthService auth, PasswordResetService resets)
    {
        _auth = auth;
        _resets = resets;
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

    // Vulnerability #35 (BOLA + account takeover, producer/consumer chain): a
    // real password-reset flow only ever emails the token to the account's own
    // address -- the caller who *requests* a reset never learns it directly.
    // This demo has no mail server, so (matching a shortcut real teams
    // sometimes take "just for local testing" and then forget to remove) the
    // token is returned straight in the response body instead. Combined with
    // no rate-limiting and no requirement that the caller already prove they
    // own the email, this turns into a genuine two-step account-takeover
    // chain against ANY known email address:
    //   1. POST /api/auth/forgot-password {email: victim@x.test} -> {resetToken: "..."}
    //   2. POST /api/auth/reset-password  {token: "...", newPassword: "attacker-chosen"}
    // Neither request alone demonstrates account takeover; step 2's `token`
    // must come from step 1's own response for the exploit to work, exactly
    // the producer-in-response -> consumer-in-later-request shape
    // void/go/sequence.go's resource-state-graph is built to track.
    [HttpPost("forgot-password")]
    [ProducesResponseType(typeof(ForgotPasswordResponse), 200)]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordRequest request)
    {
        if (!ModelState.IsValid)
        {
            return ValidationProblem(ModelState);
        }
        try
        {
            var token = await _resets.RequestResetAsync(request.Email);
            return Ok(new ForgotPasswordResponse { ResetToken = token });
        }
        catch (InvalidResetTokenException)
        {
            // Deliberately identical response shape to a real request, so this
            // endpoint can't be used to enumerate which emails have accounts --
            // the "vulnerability" here is the token leak above, not this branch.
            return Ok(new ForgotPasswordResponse { ResetToken = "" });
        }
    }

    // Vulnerability #34 (sequence-only): see PasswordResetService.ResetAsync's
    // own comment on why UsedAt is set but never checked.
    [HttpPost("reset-password")]
    [ProducesResponseType(200)]
    public async Task<IActionResult> ResetPassword(ResetPasswordRequest request)
    {
        if (!ModelState.IsValid)
        {
            return ValidationProblem(ModelState);
        }
        try
        {
            await _resets.ResetAsync(request.Token, request.NewPassword);
            return Ok(new { reset = true });
        }
        catch (InvalidResetTokenException)
        {
            return BadRequest(new { error = "Invalid or expired token." });
        }
    }
}
