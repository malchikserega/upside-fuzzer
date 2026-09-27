using System.ComponentModel.DataAnnotations;

namespace TeamFlow.Core.Dtos;

public class ForgotPasswordRequest
{
    [Required, EmailAddress]
    public string Email { get; set; } = "";
}

// Vulnerability #35 (BOLA + account takeover via producer/consumer chain): the
// token is returned directly in this response instead of only being emailed --
// see AuthController.ForgotPassword's own comment for why that turns this into
// a genuine two-step sequence bug rather than a same-request leak.
public class ForgotPasswordResponse
{
    public string ResetToken { get; set; } = "";
}

public class ResetPasswordRequest
{
    [Required]
    public string Token { get; set; } = "";

    [Required, StringLength(64, MinimumLength = 8)]
    public string NewPassword { get; set; } = "";
}
