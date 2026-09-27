namespace TeamFlow.Core.Entities;

public class Organization
{
    public int Id { get; set; }
    public string Name { get; set; } = "";
    public decimal CreditBalance { get; set; } = 100m;
}
