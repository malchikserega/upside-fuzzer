using Microsoft.EntityFrameworkCore;
using TeamFlow.Core.Dtos;
using TeamFlow.Infrastructure.Data;

namespace TeamFlow.Infrastructure.Services;

public class BulkTaskService
{
    private readonly TeamFlowDbContext _db;

    public BulkTaskService(TeamFlowDbContext db)
    {
        _db = db;
    }

    // Vulnerability #40 (mass assignment): projectId comes from the route (the
    // caller's own project) but each item's AssignedUserId is trusted with no
    // check that the target user belongs to the SAME organization as that
    // project -- a single bulk-update call can hand tasks off to a user in a
    // completely different tenant. Also note this method updates whatever
    // TaskId each item names, without even checking it belongs to {projectId}
    // at all (see BulkDeleteAsync's near-identical gap for the read/delete
    // side of the same missing check).
    public async Task<int> BulkUpdateAsync(int projectId, List<BulkUpdateItem> items)
    {
        var ids = items.Select(i => i.TaskId).ToList();
        var tasks = await _db.ProjectTasks.Where(t => ids.Contains(t.Id)).ToDictionaryAsync(t => t.Id);
        var updated = 0;
        foreach (var item in items)
        {
            if (!tasks.TryGetValue(item.TaskId, out var task))
            {
                continue;
            }
            if (item.Status.HasValue)
            {
                task.Status = item.Status.Value;
            }
            if (item.AssignedUserId.HasValue)
            {
                task.AssignedUserId = item.AssignedUserId; // <-- the bug: no cross-org check
            }
            updated++;
        }
        await _db.SaveChangesAsync();
        return updated;
    }

    // Vulnerability #41 (BOLA): projectId is accepted as a route parameter to
    // make the endpoint LOOK scoped to the caller's own project, but taskIds is
    // matched against the database with no filter on ProjectId at all -- any
    // task id from any project, in any organization, deletes successfully
    // through this call regardless of which {projectId} the request was sent to.
    public async Task<int> BulkDeleteAsync(int projectId, List<int> taskIds)
    {
        var tasks = await _db.ProjectTasks.Where(t => taskIds.Contains(t.Id)).ToListAsync(); // <-- the bug: no `&& t.ProjectId == projectId`
        _db.ProjectTasks.RemoveRange(tasks);
        await _db.SaveChangesAsync();
        return tasks.Count;
    }
}
