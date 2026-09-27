using Microsoft.EntityFrameworkCore;
using TeamFlow.Core.Entities;
using TeamFlow.Infrastructure.Data;

namespace TeamFlow.Infrastructure.Services;

public class InvitationNotFoundException : Exception
{
}

public class InvitationNotPendingException : Exception
{
}

public class InvitationService
{
    private readonly TeamFlowDbContext _db;
    private readonly JwtTokenService _jwt;

    public InvitationService(TeamFlowDbContext db, JwtTokenService jwt)
    {
        _db = db;
        _jwt = jwt;
    }

    public async Task<Invitation> CreateAsync(int organizationId, int invitedByUserId, string email, UserRole role)
    {
        var invitation = new Invitation
        {
            OrganizationId = organizationId,
            Email = email,
            Role = role,
            InvitedByUserId = invitedByUserId,
            Token = Guid.NewGuid().ToString("N"),
        };
        _db.Invitations.Add(invitation);
        await _db.SaveChangesAsync();
        return invitation;
    }

    public async Task<Invitation> GetByTokenAsync(string token)
    {
        return await _db.Invitations.FirstOrDefaultAsync(i => i.Token == token)
            ?? throw new InvitationNotFoundException();
    }

    public async Task<Invitation> GetAsync(int id)
    {
        return await _db.Invitations.FirstOrDefaultAsync(i => i.Id == id)
            ?? throw new InvitationNotFoundException();
    }

    public async Task RevokeAsync(int id)
    {
        var invitation = await GetAsync(id);
        invitation.Status = InvitationStatus.Revoked;
        await _db.SaveChangesAsync();
    }

    // ── Vulnerability #27: sequence-only, BOLA + privilege escalation ──
    //
    // Lets the caller change a still-Pending invitation's Role with no check that
    // the caller is the org owner/admin who created it, and no check that the
    // requested role is no higher than the caller's own. A single-request
    // fuzzer sending this PUT in isolation observes nothing wrong -- the
    // invitation row just silently changes. The actual privilege escalation
    // only becomes externally observable three requests later, after Accept
    // creates a real User account at the now-elevated role:
    //   1. POST /api/organizations/{id}/invitations  {email, role: Member}
    //   2. PUT  /api/invitations/{id}                 {role: Admin}   <- this method
    //   3. POST /api/invitations/{token}/accept        -> creates an Admin account
    // void/go's sequence engine chains exactly this shape: step 2's path parameter
    // and step 3's token both come from step 1's response, and the resource-state-
    // graph tracks the invitation's lifecycle across all three calls.
    public async Task<Invitation> UpdateRoleAsync(int id, UserRole role)
    {
        var invitation = await GetAsync(id);
        if (invitation.Status != InvitationStatus.Pending)
        {
            throw new InvitationNotPendingException();
        }
        invitation.Role = role; // <-- the bug: no check against the caller's own role
        await _db.SaveChangesAsync();
        return invitation;
    }

    // ── Vulnerability #26: BOLA ──
    //
    // Accept never checks that the authenticated caller's own email matches
    // invitation.Email -- any logged-in user, from any organization, can accept
    // any *other* pending invitation by token and be added to the inviting
    // organization at the invited role. A correctly-implemented flow would
    // require the invitation to be accepted either anonymously (creating a new
    // account tied to invitation.Email specifically) or by a caller whose own
    // email matches.
    //
    // ── Vulnerability #28: sequence-only race condition ──
    //
    // Status is checked, then (after an artificial delay widening the window,
    // matching CreditsService.WithdrawAsync's established pattern) written --
    // no transaction, no row lock. Two near-simultaneous Accept calls against
    // the SAME still-Pending invitation can both pass the check before either
    // commits the Accepted status, creating two separate User rows from one
    // invitation. Only reachable via a create-invitation -> accept -> accept
    // (again, concurrently) chain; a single Accept call can never demonstrate
    // the duplicate-account outcome by itself.
    public async Task<User> AcceptAsync(string token, string password)
    {
        var invitation = await _db.Invitations.FirstOrDefaultAsync(i => i.Token == token)
            ?? throw new InvitationNotFoundException();

        if (invitation.Status != InvitationStatus.Pending) // check
        {
            throw new InvitationNotPendingException();
        }

        await Task.Delay(150); // widens the TOCTOU window, same rationale as CreditsService

        var user = new User
        {
            OrganizationId = invitation.OrganizationId,
            Email = invitation.Email,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(password),
            Role = invitation.Role,
        };
        _db.Users.Add(user);

        invitation.Status = InvitationStatus.Accepted; // act -- no re-check, no locking
        invitation.AcceptedUserId = user.Id;
        await _db.SaveChangesAsync();
        return user;
    }

    public string IssueToken(User user) => _jwt.IssueToken(user);
}
