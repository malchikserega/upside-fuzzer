namespace TeamFlow.Core.Dtos;

public class ProjectDto
{
    public int Id { get; set; }
    public int OrganizationId { get; set; }
    public string Name { get; set; } = "";
    public string? Description { get; set; }
}
