using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using TeamFlow.Core.Entities;
using TeamFlow.Infrastructure.Data;

namespace TeamFlow.Infrastructure.Services;

public class ApiKeyNotFoundException : Exception
{
}

public class ApiKeyService
{
    private readonly TeamFlowDbContext _db;

    // ── Vulnerability #32: sequence-only ──
    //
    // A process-wide cache mapping a key's hash to its owning user id, added as a
    // real performance optimization (avoid hitting the database to validate an
    // API key on every single request) -- but ValidateAsync below only ever
    // *populates* this cache, and RevokeAsync only ever updates the database
    // row. Nothing anywhere invalidates a cache entry once it exists.
    //
    // A single-request fuzzer probing a freshly-revoked key from a cold process
    // (nothing cached yet) would correctly see it rejected -- ValidateAsync
    // falls through to the database check, which excludes revoked keys. The bug
    // only manifests through the specific sequence create -> use (populates the
    // cache with a valid entry) -> revoke -> use again (still succeeds, since
    // the second call hits the cache branch and never reaches the database
    // check at all). void/go's resource-state-graph tracks the key's own
    // lifecycle (Created -> ... -> Invalidated) across exactly these calls.
    private static readonly ConcurrentDictionary<string, int> ValidatedKeyCache = new();

    public ApiKeyService(TeamFlowDbContext db)
    {
        _db = db;
    }

    private static string Hash(string rawKey)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawKey));
        return Convert.ToHexString(bytes);
    }

    public async Task<(ApiKey entity, string rawKey)> CreateAsync(int userId, string label)
    {
        var rawKey = "tfk_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(24)).ToLowerInvariant();
        var entity = new ApiKey { UserId = userId, Label = label, KeyHash = Hash(rawKey) };
        _db.ApiKeys.Add(entity);
        await _db.SaveChangesAsync();
        return (entity, rawKey);
    }

    // Vulnerability #33 (BOLA): no check that {id} in the route matches the
    // caller's own user id -- any authenticated caller can list any other
    // user's API-key labels and creation/revocation metadata (not the raw keys
    // themselves, which are never persisted, but enough to see who has active
    // keys and when they were made).
    public async Task<List<ApiKey>> ListAsync(int userId)
    {
        return await _db.ApiKeys.Where(k => k.UserId == userId).ToListAsync();
    }

    public async Task RevokeAsync(int id)
    {
        var key = await _db.ApiKeys.FirstOrDefaultAsync(k => k.Id == id)
            ?? throw new ApiKeyNotFoundException();
        key.RevokedAt = DateTime.UtcNow; // <-- only updates the DB row; ValidatedKeyCache above is never touched
        await _db.SaveChangesAsync();
    }

    // Called by ApiKeyAuthMiddleware on every request carrying an X-Api-Key header.
    public async Task<User?> ValidateAsync(string rawKey)
    {
        var hash = Hash(rawKey);
        if (ValidatedKeyCache.TryGetValue(hash, out var cachedUserId))
        {
            return await _db.Users.FirstOrDefaultAsync(u => u.Id == cachedUserId); // <-- the bug: never re-checks RevokedAt
        }
        var entity = await _db.ApiKeys.FirstOrDefaultAsync(k => k.KeyHash == hash && k.RevokedAt == null);
        if (entity is null)
        {
            return null;
        }
        ValidatedKeyCache[hash] = entity.UserId;
        return await _db.Users.FirstOrDefaultAsync(u => u.Id == entity.UserId);
    }
}
