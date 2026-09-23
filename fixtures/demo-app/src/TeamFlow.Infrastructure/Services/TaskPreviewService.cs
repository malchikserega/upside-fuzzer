using Microsoft.EntityFrameworkCore;
using Scriban;
using TeamFlow.Infrastructure.Data;

namespace TeamFlow.Infrastructure.Services;

public class TaskPreviewService
{
    private readonly TeamFlowDbContext _db;

    public TaskPreviewService(TeamFlowDbContext db)
    {
        _db = db;
    }

    // Vulnerability #15 (SSTI + reflected XSS on the same endpoint):
    //
    // "Render the task description as a template so users can reference {{ project.name }}
    // etc. in their notes" is a real, plausible feature -- and Scriban (like any
    // general-purpose template engine given untrusted template *text*, not just
    // untrusted template *data*) will happily evaluate arbitrary expressions,
    // including arithmetic: {{ 1337*1337 }} -> 1787569, exactly the payload shape
    // void/go/mutations.go's ssti category already sends. Task.Description is
    // user-controlled at creation time, so the SSTI is fully attacker-reachable.
    //
    // Separately, when format=html, the rendered output is written directly into
    // the response with no HTML-encoding at all -- a second, independent bug
    // (reflected XSS) living on the same endpoint, since the *result* of evaluating
    // a malicious template is itself attacker-influenced content that then gets
    // reflected unescaped.
    public async Task<string> RenderAsync(int taskId, string format)
    {
        var task = await _db.ProjectTasks.FirstOrDefaultAsync(t => t.Id == taskId)
            ?? throw new TaskNotFoundException();
        var project = await _db.Projects.FirstOrDefaultAsync(p => p.Id == task.ProjectId);

        var template = Template.Parse(task.Description ?? "");
        var rendered = template.HasErrors
            ? task.Description ?? ""
            : template.Render(new { task = new { task.Title, task.Status }, project = new { Name = project?.Name ?? "" } });

        if (string.Equals(format, "html", StringComparison.OrdinalIgnoreCase))
        {
            // <-- the XSS: `rendered` is written into an HTML response with zero encoding.
            return $"<html><body><h1>{task.Title}</h1><div class=\"preview\">{rendered}</div></body></html>";
        }
        return rendered;
    }
}
