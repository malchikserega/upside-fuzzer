namespace TeamFlow.Core.Entities;

public class Webhook
{
    public int Id { get; set; }
    public int OrganizationId { get; set; }
    public string Url { get; set; } = "";
    public string Secret { get; set; } = "";
    public bool Verified { get; set; }
}
