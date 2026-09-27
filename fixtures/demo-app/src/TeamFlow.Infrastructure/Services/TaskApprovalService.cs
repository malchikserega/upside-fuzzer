using Microsoft.EntityFrameworkCore;
using TeamFlow.Core.Entities;
using TeamFlow.Infrastructure.Data;

namespace TeamFlow.Infrastructure.Services;

public class TaskApprovalService
{
    private const decimal ApprovalCreditReward = 5m;

    private readonly TeamFlowDbContext _db;

    public TaskApprovalService(TeamFlowDbContext db)
    {
        _db = db;
    }

    public async Task<ProjectTask> SubmitForReviewAsync(int taskId)
    {
        var task = await _db.ProjectTasks.FirstOrDefaultAsync(t => t.Id == taskId)
            ?? throw new TaskNotFoundException();
        task.ApprovalStatus = ProjectTaskApprovalStatus.PendingReview;
        task.SubmittedForReviewAt = DateTime.UtcNow;
        await _db.SaveChangesAsync();
        return task;
    }

    // ── Vulnerability #38 (missing state-machine validation): Approve never
    // checks that ApprovalStatus == PendingReview first -- a task can be
    // approved directly from None (skipping SubmitForReview entirely) or
    // re-approved from an already-Approved or even Rejected state. The intended
    // flow is Submit -> Approve, but nothing enforces it.
    //
    // ── Vulnerability #39 (sequence-only, duplicate side effect): because the
    // same gap lets Approve run twice against one task, the credit reward below
    // fires again on the second call -- ApprovalCreditCount and the org's
    // CreditBalance both increment a second time for work approved only once.
    // A single Approve call looks completely correct in isolation (task moves
    // to Approved, one credit granted); the duplication is only externally
    // observable through the chain submit -> approve -> approve (again), by
    // comparing ApprovalCreditCount/CreditBalance before and after the SECOND
    // call specifically.
    public async Task<ProjectTask> ApproveAsync(int taskId, int approvedByUserId)
    {
        var task = await _db.ProjectTasks.FirstOrDefaultAsync(t => t.Id == taskId)
            ?? throw new TaskNotFoundException();

        task.ApprovalStatus = ProjectTaskApprovalStatus.Approved; // <-- no check of prior state
        task.ApprovedByUserId = approvedByUserId;
        task.ApprovalCreditCount++;

        var project = await _db.Projects.FirstOrDefaultAsync(p => p.Id == task.ProjectId);
        if (project is not null)
        {
            var org = await _db.Organizations.FirstOrDefaultAsync(o => o.Id == project.OrganizationId);
            if (org is not null)
            {
                org.CreditBalance += ApprovalCreditReward; // fires again on every repeated Approve call
            }
        }

        await _db.SaveChangesAsync();
        return task;
    }

    public async Task<ProjectTask> RejectAsync(int taskId)
    {
        var task = await _db.ProjectTasks.FirstOrDefaultAsync(t => t.Id == taskId)
            ?? throw new TaskNotFoundException();
        task.ApprovalStatus = ProjectTaskApprovalStatus.Rejected;
        await _db.SaveChangesAsync();
        return task;
    }
}
