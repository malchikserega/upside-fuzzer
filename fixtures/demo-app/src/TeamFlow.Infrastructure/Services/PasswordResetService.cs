using Microsoft.EntityFrameworkCore;
using TeamFlow.Core.Entities;
using TeamFlow.Infrastructure.Data;

namespace TeamFlow.Infrastructure.Services;

public class InvalidResetTokenException : Exception
{
}

public class PasswordResetService
{
    private readonly TeamFlowDbContext _db;

    public PasswordResetService(TeamFlowDbContext db)
    {
        _db = db;
    }

    // ── Vulnerability #35: BOLA + account takeover, producer/consumer chain ──
    //
    // See AuthController.ForgotPassword's own comment for the full writeup of
    // why returning the token directly (rather than only emailing it, which
    // this demo has no mail server to actually do) turns "anyone can request a
    // reset for anyone's email" into a genuine two-step account-takeover chain
    // rather than a same-request leak.
    public async Task<string> RequestResetAsync(string email)
    {
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == email)
            ?? throw new InvalidResetTokenException(); // reuse: "no such user" and "invalid token" look identical to the caller either way

        var token = new PasswordResetToken
        {
            UserId = user.Id,
            Token = Guid.NewGuid().ToString("N"),
            ExpiresAt = DateTime.UtcNow.AddHours(1),
        };
        _db.PasswordResetTokens.Add(token);
        await _db.SaveChangesAsync();
        return token.Token;
    }

    // ── Vulnerability #34: sequence-only, token replay ──
    //
    // ExpiresAt is checked, but UsedAt is only ever *set*, never *checked* --
    // the same token can be replayed to reset the password again and again
    // until it expires. A single ResetPassword call can never demonstrate this
    // by itself; the bug only becomes observable through the chain
    // forgot-password -> reset-password -> reset-password (again, same token),
    // where the second reset succeeding at all is the actual finding.
    public async Task ResetAsync(string token, string newPassword)
    {
        var resetToken = await _db.PasswordResetTokens.FirstOrDefaultAsync(t => t.Token == token)
            ?? throw new InvalidResetTokenException();

        if (resetToken.ExpiresAt < DateTime.UtcNow)
        {
            throw new InvalidResetTokenException();
        }

        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == resetToken.UserId)
            ?? throw new InvalidResetTokenException();

        user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(newPassword);
        resetToken.UsedAt = DateTime.UtcNow; // <-- set, but ResetAsync never checks it above -- the bug
        await _db.SaveChangesAsync();
    }
}
