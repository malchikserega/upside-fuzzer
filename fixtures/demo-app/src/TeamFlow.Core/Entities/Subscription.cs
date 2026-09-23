namespace TeamFlow.Core.Entities;

public class Subscription
{
    public int Id { get; set; }
    public int OrganizationId { get; set; }
    public SubscriptionPlan Plan { get; set; } = SubscriptionPlan.Free;
    public int Quota { get; set; } = 5;
    public int UsedQuota { get; set; }
}
