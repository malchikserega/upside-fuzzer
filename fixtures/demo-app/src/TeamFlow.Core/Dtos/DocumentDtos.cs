namespace TeamFlow.Core.Dtos;

public class DocumentDto
{
    public int Id { get; set; }
    public int ProjectId { get; set; }
    public string FileName { get; set; } = "";
    public string ContentType { get; set; } = "";
}
