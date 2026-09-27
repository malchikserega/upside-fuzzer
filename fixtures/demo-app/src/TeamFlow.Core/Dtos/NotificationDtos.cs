namespace TeamFlow.Core.Dtos;

public class NotificationDto
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public string Type { get; set; } = "";
    public string Message { get; set; } = "";
    public bool Read { get; set; }
}
