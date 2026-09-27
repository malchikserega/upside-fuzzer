using TeamFlow.Core.Entities;

namespace TeamFlow.Core.Dtos;

public class SubscriptionDto
{
    public int OrganizationId { get; set; }
    public string Plan { get; set; } = "";
    public int Quota { get; set; }
    public int UsedQuota { get; set; }
}

public class ChangePlanRequest
{
    public SubscriptionPlan Plan { get; set; }
}
