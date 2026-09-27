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

    // Approval workflow (separate state machine from Status above -- see
    // TaskApprovalService for the two vulnerabilities built on it).
    public ProjectTaskApprovalStatus ApprovalStatus { get; set; } = ProjectTaskApprovalStatus.None;
    public DateTime? SubmittedForReviewAt { get; set; }
    public int? ApprovedByUserId { get; set; }

    // Counts every time Approve has actually run its side effect (crediting the
    // assignee's organization) -- used only to prove vulnerability #26 (double-
    // approve re-triggers the credit) actually fired more than once for the same task.
    public int ApprovalCreditCount { get; set; }
}
