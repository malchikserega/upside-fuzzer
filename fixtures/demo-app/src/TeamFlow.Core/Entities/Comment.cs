namespace TeamFlow.Core.Entities;

public class Comment
{
    public int Id { get; set; }
    public int TaskId { get; set; }
    public int AuthorUserId { get; set; }
    public string Body { get; set; } = "";
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
