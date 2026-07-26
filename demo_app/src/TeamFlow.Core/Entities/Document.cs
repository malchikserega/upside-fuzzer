namespace TeamFlow.Core.Entities;

public class Document
{
    public int Id { get; set; }
    public int ProjectId { get; set; }
    public string FileName { get; set; } = "";
    public string StoragePath { get; set; } = "";
    public string ContentType { get; set; } = "";
    public int UploadedByUserId { get; set; }
}
