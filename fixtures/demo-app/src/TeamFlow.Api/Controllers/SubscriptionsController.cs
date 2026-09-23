using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using TeamFlow.Core.Dtos;
using TeamFlow.Infrastructure.Services;

namespace TeamFlow.Api.Controllers;

[ApiController]
[Route("api")]
[Authorize]
public class SubscriptionsController : ControllerBase
{
    private readonly SubscriptionService _subscriptions;

    public SubscriptionsController(SubscriptionService subscriptions)
    {
        _subscriptions = subscriptions;
    }

    [HttpGet("organizations/{id:int}/subscription")]
    [ProducesResponseType(typeof(SubscriptionDto), 200)]
    public async Task<IActionResult> Get(int id)
    {
        try
        {
            var sub = await _subscriptions.GetAsync(id);
            return Ok(new SubscriptionDto { OrganizationId = sub.OrganizationId, Plan = sub.Plan.ToString(), Quota = sub.Quota, UsedQuota = sub.UsedQuota });
        }
        catch (KeyNotFoundException)
        {
            return NotFound();
        }
    }

    // Vulnerability #36 (business-logic flaw): see
    // SubscriptionService.ChangePlanAsync's own comment on why a downgrade can
    // leave UsedQuota permanently above the new Quota.
    [HttpPost("organizations/{id:int}/subscription/change-plan")]
    [ProducesResponseType(typeof(SubscriptionDto), 200)]
    public async Task<IActionResult> ChangePlan(int id, ChangePlanRequest request)
    {
        try
        {
            var sub = await _subscriptions.ChangePlanAsync(id, request.Plan);
            return Ok(new SubscriptionDto { OrganizationId = sub.OrganizationId, Plan = sub.Plan.ToString(), Quota = sub.Quota, UsedQuota = sub.UsedQuota });
        }
        catch (KeyNotFoundException)
        {
            return NotFound();
        }
    }

    // Vulnerability #37 (race condition): see SubscriptionService.ConsumeAsync's
    // own comment for the check-then-act TOCTOU window.
    [HttpPost("organizations/{id:int}/subscription/consume")]
    [ProducesResponseType(typeof(SubscriptionDto), 200)]
    [ProducesResponseType(409)]
    public async Task<IActionResult> Consume(int id, [FromQuery] int amount = 1)
    {
        try
        {
            var sub = await _subscriptions.ConsumeAsync(id, amount);
            return Ok(new SubscriptionDto { OrganizationId = sub.OrganizationId, Plan = sub.Plan.ToString(), Quota = sub.Quota, UsedQuota = sub.UsedQuota });
        }
        catch (QuotaExceededException)
        {
            return Conflict("Quota exceeded.");
        }
        catch (KeyNotFoundException)
        {
            return NotFound();
        }
    }
}
