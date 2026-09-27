using Microsoft.EntityFrameworkCore;
using TeamFlow.Infrastructure.Data;

namespace TeamFlow.Infrastructure.Services;

public class InsufficientCreditsException : Exception
{
}

public class CreditsService
{
    private readonly TeamFlowDbContext _db;

    public CreditsService(TeamFlowDbContext db)
    {
        _db = db;
    }

    // Vulnerability #23 (race condition / TOCTOU): check-then-act with no
    // transaction, no row lock, and no optimistic-concurrency token -- two
    // concurrent withdrawals can both pass the balance check before either commits,
    // letting the org withdraw more credits than it actually has. The artificial
    // delay between check and write is what makes the race window reliably wide
    // enough to hit in a demo (`-race-mode`'s burst probing sends several
    // near-simultaneous requests, not just two).
    public async Task<decimal> WithdrawAsync(int organizationId, decimal amount)
    {
        var org = await _db.Organizations.FirstOrDefaultAsync(o => o.Id == organizationId)
            ?? throw new KeyNotFoundException("Organization not found.");

        if (org.CreditBalance < amount) // check
        {
            throw new InsufficientCreditsException();
        }

        await Task.Delay(150); // widens the TOCTOU window so it's reliably reachable in a short demo run

        org.CreditBalance -= amount; // act -- no re-check, no locking
        await _db.SaveChangesAsync();
        return org.CreditBalance;
    }
}
