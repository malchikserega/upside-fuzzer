namespace TeamFlow.Api.Dtos;

// Vulnerability #17 (path traversal): FileName is used verbatim to build the
// on-disk storage path -- see TeamFlow.Infrastructure.Services.FileStorageService.
// A genuine multipart/form-data endpoint (not JSON+base64) -- exercises
// grammarc/multipart.py's real multipart-template generation, not just the JSON
// body path every other endpoint in this demo already covers. Lives in the Api
// project (not Core) because IFormFile is an ASP.NET Core HTTP-binding concern.
public class UploadDocumentForm
{
    public string FileName { get; set; } = "";
    public IFormFile? File { get; set; }
}
