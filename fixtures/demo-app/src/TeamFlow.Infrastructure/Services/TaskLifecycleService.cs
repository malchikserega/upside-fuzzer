using Microsoft.EntityFrameworkCore;
using TeamFlow.Core.Entities;
using TeamFlow.Infrastructure.Data;

namespace TeamFlow.Infrastructure.Services;

public class TaskNotFoundException : Exception
{
}

public class TaskLifecycleService
{
    private readonly TeamFlowDbContext _db;

    public TaskLifecycleService(TeamFlowDbContext db)
    {
        _db = db;
    }

    // ── Vulnerability #16: coverage-guided-only, findable via state-aware sequencing ──
    //
    // Restore assumes every Archived task was archived through a (never-actually-
    // implemented) dedicated "archive workflow" that would have populated real
    // archive metadata. In this codebase the ONLY way to reach Archived is the
    // generic PUT /api/tasks/{id} status update -- which never sets that metadata --
    // so the assumption is unconditionally false, and Restore always throws on a
    // genuinely archived task.
    //
    // A stateless, single-request fuzzer can never trigger this: it requires (1)
    // creating a task, (2) transitioning it to Archived via a PRIOR request whose
    // response supplies the id used in step 3, (3) THEN calling Restore with that
    // same id. void/go/sequence.go's producer/consumer chaining plus Top-20 #12's
    // state-reward search (which specifically rewards reaching a never-before-seen
    // *workflow shape*, not just a new coverage edge) is what builds and keeps
    // exploring exactly this 2-3 step chain.
    public async Task RestoreAsync(int taskId)
    {
        var task = await _db.ProjectTasks.FirstOrDefaultAsync(t => t.Id == taskId)
            ?? throw new TaskNotFoundException();

        if (task.Status == ProjectTaskStatus.Archived)
        {
            var metadata = LoadArchiveMetadata(task); // always null in this codebase
            var restoredBy = metadata!.OriginalAssigneeEmail.ToUpperInvariant(); // NullReferenceException
            task.Status = ProjectTaskStatus.Todo;
            task.ArchivedAt = null;
            _ = restoredBy;
        }
        else
        {
            task.Status = ProjectTaskStatus.Todo;
        }
        await _db.SaveChangesAsync();
    }

    private sealed class ArchiveMetadata
    {
        public string OriginalAssigneeEmail { get; set; } = "";
    }

    // Every real archive-workflow implementation was removed in a later refactor;
    // this lookup was left behind and always returns null, which is exactly the
    // trap RestoreAsync falls into above.
    private static ArchiveMetadata? LoadArchiveMetadata(ProjectTask task) => null;

    public async Task<ProjectTask> GetAsync(int taskId)
    {
        return await _db.ProjectTasks.FirstOrDefaultAsync(t => t.Id == taskId)
            ?? throw new TaskNotFoundException();
    }

    // ── Vulnerability #21: coverage-guided-only, findable via nested-branch coverage reward ──
    //
    // No single constant to extract here (unlike #20) -- the vulnerable region is a
    // narrow *combination* of independently-checked conditions nested 3 levels deep,
    // plus an off-by-one boundary inside the innermost branch. A stateless random
    // fuzzer has to satisfy all of them simultaneously by chance (an exact 6-char
    // region string, a 4-value integer band, an exact-length code) -- vanishingly
    // unlikely in one shot. Coverage-guided search doesn't need to: every nested
    // `if` reached for the first time is its own new coverage edge, so
    // void/go/worker.go's corpus retention keeps and mutates *any* input that got
    // one level deeper, closing in on the full path incrementally. Once inside the
    // VerificationLevel band, Top-20 #14's boundary-aware integer mutation
    // (min/max +-1 candidates) finds the one crashing value fast.
    //
    // The gate itself is a plain, non-async method for the same reason IsBackdoorCode
    // is in CouponService: SharpFuzz's basic-block probes (and ConstantExtractor) never
    // see inside a compiler-generated async state-machine (`<Method>d__N`), so nested
    // `if`s written directly in `async Task<bool> TryUnlockAsync(...)` would produce
    // zero incremental coverage signal as the fuzzer got deeper into them. Written as
    // an ordinary method on TaskLifecycleService, every nested branch -- and the 41/44
    // ints, the "EU-WEST" string, and the length check -- are all real IL on an
    // instrumented type, exactly as the mechanism this endpoint demonstrates requires.
    private static bool PassesUnlockGate(int verificationLevel, string? region, string? unlockCode, out int slot)
    {
        slot = -1;
        if (verificationLevel < 41 || verificationLevel > 44) return false;
        if (!string.Equals(region, "EU-WEST", StringComparison.Ordinal)) return false;
        if (unlockCode is null || unlockCode.Length != 6) return false;
        slot = verificationLevel - 41; // 0..3
        return true;
    }

    public async Task<bool> TryUnlockAsync(int taskId, int verificationLevel, string? region, string? unlockCode)
    {
        var task = await _db.ProjectTasks.FirstOrDefaultAsync(t => t.Id == taskId)
            ?? throw new TaskNotFoundException();

        if (!PassesUnlockGate(verificationLevel, region, unlockCode, out var slot))
        {
            return false;
        }

        var buckets = new[] { "a", "b", "c" }; // only 3 slots -- slot==3 (level 44) overruns it
        task.Unlocked = true;
        await _db.SaveChangesAsync();
        _ = buckets[slot]; // IndexOutOfRangeException when verificationLevel == 44
        return true;
    }
}
