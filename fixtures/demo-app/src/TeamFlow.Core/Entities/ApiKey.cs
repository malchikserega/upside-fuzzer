namespace TeamFlow.Core.Entities;

public class ApiKey
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public string Label { get; set; } = "";
    public string KeyHash { get; set; } = "";
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? RevokedAt { get; set; }
}
