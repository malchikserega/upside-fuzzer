using System.ComponentModel.DataAnnotations;
using TeamFlow.Core.Entities;

namespace TeamFlow.Core.Dtos;

public class TaskDto
{
    public int Id { get; set; }
    public int ProjectId { get; set; }
    public string Title { get; set; } = "";
    public string? Description { get; set; }
    public string Status { get; set; } = "";
    public int? AssignedUserId { get; set; }
}

// Vulnerability #11 is intentionally clean -- this DTO exists purely to give
// grammarc's Top-20 #14 constraint-aware boundary mutation (min/max/length) real
// declared bounds to fuzz against: [Range]/[StringLength] round-trip through
// analyzer/'s Roslyn constraint extraction into templates.export.json's per-segment
// min_length/max_length/minimum/maximum fields.
public class CreateTaskRequest
{
    [Required, StringLength(120, MinimumLength = 3)]
    public string Title { get; set; } = "";

    [StringLength(2000)]
    public string? Description { get; set; }

    [Range(1, 9999)]
    public int? AssignedUserId { get; set; }
}

public class UpdateTaskRequest
{
    [StringLength(120, MinimumLength = 3)]
    public string? Title { get; set; }

    [StringLength(2000)]
    public string? Description { get; set; }

    // Deliberately free-form: this generic update endpoint accepts a raw status
    // string and lets a task be pushed to Archived directly, no dedicated
    // "archive workflow" endpoint involved -- see vulnerability #16.
    public ProjectTaskStatus? Status { get; set; }

    public int? AssignedUserId { get; set; }
}

public class UnlockRequest
{
    public int VerificationLevel { get; set; }
    public string? Region { get; set; }
    public string? UnlockCode { get; set; }
}
