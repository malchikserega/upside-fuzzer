namespace TeamFlow.Core.Entities;

// Named ProjectTaskStatus (not "TaskStatus") to avoid colliding with
// System.Threading.Tasks.TaskStatus under ImplicitUsings.
public enum ProjectTaskStatus
{
    Todo,
    InProgress,
    Archived,
    Done,
}
