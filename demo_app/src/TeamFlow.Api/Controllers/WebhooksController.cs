using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using TeamFlow.Core.Dtos;
using TeamFlow.Infrastructure.Services;

namespace TeamFlow.Api.Controllers;

[ApiController]
[Route("api")]
[Authorize]
public class WebhooksController : ControllerBase
{
    private readonly WebhookService _webhooks;

    public WebhooksController(WebhookService webhooks)
    {
        _webhooks = webhooks;
    }

    // Vulnerability #19 (SSRF): see WebhookService.TestAsync's own doc comment.
    [HttpPost("organizations/{id:int}/webhooks/test")]
    [ProducesResponseType(200)]
    public async Task<IActionResult> Test(int id, TestWebhookRequest request)
    {
        if (!ModelState.IsValid)
        {
            return ValidationProblem(ModelState);
        }
        try
        {
            var (statusCode, body) = await _webhooks.TestAsync(id, request.Url);
            return Ok(new { fetchedStatusCode = statusCode, bodySnippet = body });
        }
        catch (HttpRequestException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
        catch (KeyNotFoundException)
        {
            return NotFound();
        }
    }

    [HttpPost("organizations/{id:int}/webhooks")]
    [ProducesResponseType(typeof(WebhookDto), 201)]
    public async Task<IActionResult> Save(int id, TestWebhookRequest request)
    {
        if (!ModelState.IsValid)
        {
            return ValidationProblem(ModelState);
        }
        var webhook = await _webhooks.SaveAsync(id, request.Url);
        return Created($"/api/webhooks/{webhook.Id}", new WebhookDto { Id = webhook.Id, Url = webhook.Url, Verified = webhook.Verified });
    }
}
