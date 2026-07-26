using Microsoft.EntityFrameworkCore;
using TeamFlow.Core.Entities;
using TeamFlow.Infrastructure.Data;

namespace TeamFlow.Infrastructure.Services;

public class FileStorageService
{
    private readonly TeamFlowDbContext _db;
    private readonly string _storageRoot;

    public FileStorageService(TeamFlowDbContext db, string storageRoot)
    {
        _db = db;
        _storageRoot = storageRoot;
        Directory.CreateDirectory(_storageRoot);
    }

    // Vulnerability #17 (path traversal): fileName comes straight from the client
    // (the multipart form field) and is combined into the on-disk path with no
    // sanitization at all. Path.Combine does NOT protect against this -- if the
    // second argument is itself rooted or contains "..", the traversal segments
    // simply carry through into the final path. A fileName of
    // "../../../../tmp/pwned.txt" writes outside _storageRoot entirely.
    public async Task<Document> SaveAsync(int projectId, int uploadedByUserId, string fileName, string contentType, Stream content)
    {
        var fullPath = Path.Combine(_storageRoot, fileName); // <-- the bug
        var dir = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }
        await using (var fs = File.Create(fullPath))
        {
            await content.CopyToAsync(fs);
        }

        var doc = new Document
        {
            ProjectId = projectId,
            FileName = fileName,
            StoragePath = fileName, // stored as-given, same trust problem on the way back out
            ContentType = contentType,
            UploadedByUserId = uploadedByUserId,
        };
        _db.Documents.Add(doc);
        await _db.SaveChangesAsync();
        return doc;
    }

    // The download side is intentionally NOT vulnerable in the same way -- it
    // resolves the path from the database by numeric id, never from a raw
    // client-supplied path, giving a contrast case in the demo: same endpoint
    // *shape*, correctly implemented.
    public async Task<(byte[] bytes, Document doc)?> ReadAsync(int documentId)
    {
        var doc = await _db.Documents.FirstOrDefaultAsync(d => d.Id == documentId);
        if (doc is null)
        {
            return null;
        }
        var fullPath = Path.Combine(_storageRoot, doc.StoragePath);
        if (!File.Exists(fullPath))
        {
            return null;
        }
        return (await File.ReadAllBytesAsync(fullPath), doc);
    }
}
