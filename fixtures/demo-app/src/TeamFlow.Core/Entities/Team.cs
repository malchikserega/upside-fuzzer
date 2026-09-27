namespace TeamFlow.Core.Entities;

public class Team
{
    public int Id { get; set; }
    public int OrganizationId { get; set; }
    public string Name { get; set; } = "";
}
