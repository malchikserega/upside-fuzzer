namespace TeamFlow.Core.Entities;

public class ProjectTask
{
    public int Id { get; set; }
    public int ProjectId { get; set; }
    public string Title { get; set; } = "";
    public string? Description { get; set; }
    public ProjectTaskStatus Status { get; set; } = ProjectTaskStatus.Todo;
    public int? AssignedUserId { get; set; }
    public DateTime? ArchivedAt { get; set; }
    public bool Unlocked { get; set; }
}
