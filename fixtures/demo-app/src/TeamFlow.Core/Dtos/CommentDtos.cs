using System.ComponentModel.DataAnnotations;

namespace TeamFlow.Core.Dtos;

public class CommentDto
{
    public int Id { get; set; }
    public int TaskId { get; set; }
    public int AuthorUserId { get; set; }
    public string Body { get; set; } = "";
}

// Vulnerability #29 (mass assignment): AuthorUserId is bound directly from the
// client body -- any authenticated caller can post a comment that appears to
// have been written by an arbitrary other user.
public class CreateCommentRequest
{
    [Required, StringLength(2000, MinimumLength = 1)]
    public string Body { get; set; } = "";

    public int? AuthorUserId { get; set; }
}

public class UpdateCommentRequest
{
    [Required, StringLength(2000, MinimumLength = 1)]
    public string Body { get; set; } = "";
}
