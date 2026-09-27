using System.ComponentModel.DataAnnotations;

namespace TeamFlow.Core.Dtos;

public class WebhookDto
{
    public int Id { get; set; }
    public string Url { get; set; } = "";
    public bool Verified { get; set; }
}

// Vulnerability #19 (SSRF): the server fetches this URL itself, server-side, to
// "validate the endpoint is reachable" before saving the webhook -- see
// TeamFlow.Infrastructure.Services.WebhookService.
public class TestWebhookRequest
{
    [Required, Url]
    public string Url { get; set; } = "";
}
