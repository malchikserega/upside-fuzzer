using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using TeamFlow.Api.Dtos;
using TeamFlow.Core.Dtos;
using TeamFlow.Infrastructure.Data;
using TeamFlow.Infrastructure.Services;

namespace TeamFlow.Api.Controllers;

[ApiController]
[Route("api")]
[Authorize]
public class DocumentsController : ControllerBase
{
    private readonly TeamFlowDbContext _db;
    private readonly FileStorageService _storage;

    public DocumentsController(TeamFlowDbContext db, FileStorageService storage)
    {
        _db = db;
        _storage = storage;
    }

    private int CurrentUserId => int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);

    // Vulnerability #17 (path traversal): see FileStorageService.SaveAsync's own
    // doc comment. Genuine multipart/form-data upload -- exercises
    // grammarc/multipart.py's real multipart-template generation.
    [HttpPost("projects/{projectId:int}/documents")]
    [ProducesResponseType(typeof(DocumentDto), 201)]
    [Consumes("multipart/form-data")]
    public async Task<IActionResult> Upload(int projectId, [FromForm] UploadDocumentForm form)
    {
        var project = await _db.Projects.FirstOrDefaultAsync(p => p.Id == projectId);
        if (project is null)
        {
            return NotFound();
        }
        if (form.File is null || string.IsNullOrWhiteSpace(form.FileName))
        {
            return BadRequest("file and fileName are required.");
        }
        await using var stream = form.File.OpenReadStream();
        var doc = await _storage.SaveAsync(projectId, CurrentUserId, form.FileName, form.File.ContentType, stream);
        return Created($"/api/documents/{doc.Id}/download", new DocumentDto { Id = doc.Id, ProjectId = doc.ProjectId, FileName = doc.FileName, ContentType = doc.ContentType });
    }

    // Contrast case (vulnerability #18 is deliberately absent): resolves the
    // storage path from the database by numeric id, never from a raw client-
    // supplied path -- the correctly-implemented twin of the upload endpoint above.
    [HttpGet("documents/{id:int}/download")]
    [ProducesResponseType(200)]
    public async Task<IActionResult> Download(int id)
    {
        var result = await _storage.ReadAsync(id);
        if (result is null)
        {
            return NotFound();
        }
        var (bytes, doc) = result.Value;
        return File(bytes, string.IsNullOrEmpty(doc.ContentType) ? "application/octet-stream" : doc.ContentType, doc.FileName);
    }
}
