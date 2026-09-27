using Microsoft.EntityFrameworkCore;
using TeamFlow.Core.Entities;
using TeamFlow.Infrastructure.Data;

namespace TeamFlow.Infrastructure.Services;

public class QuotaExceededException : Exception
{
}

public class SubscriptionService
{
    private readonly TeamFlowDbContext _db;

    public SubscriptionService(TeamFlowDbContext db)
    {
        _db = db;
    }

    private static int QuotaFor(SubscriptionPlan plan) => plan switch
    {
        SubscriptionPlan.Free => 5,
        SubscriptionPlan.Pro => 50,
        SubscriptionPlan.Enterprise => 1000,
        _ => 5,
    };

    public async Task<Subscription> GetAsync(int organizationId)
    {
        return await _db.Subscriptions.FirstOrDefaultAsync(s => s.OrganizationId == organizationId)
            ?? throw new KeyNotFoundException("No subscription for this organization.");
    }

    // Vulnerability #36 (business-logic flaw): changing plans just overwrites
    // Quota to the new plan's fixed amount and never re-validates or resets
    // UsedQuota against it. Downgrading from Enterprise (1000) to Free (5)
    // while UsedQuota is, say, 300 leaves the subscription permanently over
    // quota (UsedQuota > Quota) -- ConsumeAsync below then computes a negative
    // "remaining" value forever, and every subsequent consume attempt fails in
    // a way that looks like a live incident rather than a one-time downgrade
    // decision. A real implementation would need to either block the downgrade
    // while over the new quota, or explicitly reconcile UsedQuota at
    // change-time.
    public async Task<Subscription> ChangePlanAsync(int organizationId, SubscriptionPlan plan)
    {
        var sub = await GetAsync(organizationId);
        sub.Plan = plan;
        sub.Quota = QuotaFor(plan); // <-- the bug: UsedQuota is never reconciled against the new Quota
        await _db.SaveChangesAsync();
        return sub;
    }

    // Vulnerability #37 (race condition / TOCTOU): identical shape to
    // CreditsService.WithdrawAsync -- check-then-act with an artificial delay
    // and no transaction/lock, so two near-simultaneous Consume calls can both
    // pass the remaining-quota check before either commits, letting UsedQuota
    // exceed Quota through ordinary concurrent use rather than the downgrade
    // path above.
    public async Task<Subscription> ConsumeAsync(int organizationId, int amount)
    {
        var sub = await GetAsync(organizationId);
        if (sub.UsedQuota + amount > sub.Quota) // check
        {
            throw new QuotaExceededException();
        }

        await Task.Delay(150); // widens the TOCTOU window, same rationale as CreditsService

        sub.UsedQuota += amount; // act -- no re-check, no locking
        await _db.SaveChangesAsync();
        return sub;
    }
}
