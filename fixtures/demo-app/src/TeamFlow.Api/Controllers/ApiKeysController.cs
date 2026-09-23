using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using TeamFlow.Core.Dtos;
using TeamFlow.Infrastructure.Services;

namespace TeamFlow.Api.Controllers;

[ApiController]
[Route("api")]
[Authorize]
public class ApiKeysController : ControllerBase
{
    private readonly ApiKeyService _apiKeys;

    public ApiKeysController(ApiKeyService apiKeys)
    {
        _apiKeys = apiKeys;
    }

    [HttpPost("users/{userId:int}/api-keys")]
    [ProducesResponseType(typeof(ApiKeyCreatedDto), 201)]
    public async Task<IActionResult> Create(int userId, CreateApiKeyRequest request)
    {
        if (!ModelState.IsValid)
        {
            return ValidationProblem(ModelState);
        }
        var (entity, rawKey) = await _apiKeys.CreateAsync(userId, request.Label);
        return Created($"/api/api-keys/{entity.Id}", new ApiKeyCreatedDto
        {
            Id = entity.Id,
            UserId = entity.UserId,
            Label = entity.Label,
            Revoked = false,
            Key = rawKey,
        });
    }

    // Vulnerability #33 (BOLA): see ApiKeyService.ListAsync's own comment.
    [HttpGet("users/{userId:int}/api-keys")]
    [ProducesResponseType(typeof(List<ApiKeyDto>), 200)]
    public async Task<IActionResult> List(int userId)
    {
        var keys = await _apiKeys.ListAsync(userId);
        return Ok(keys.Select(k => new ApiKeyDto { Id = k.Id, UserId = k.UserId, Label = k.Label, Revoked = k.RevokedAt != null }));
    }

    // Vulnerability #32 (sequence-only): see ApiKeyService's own class-level
    // comment on ValidatedKeyCache for the full create -> use -> revoke -> use
    // chain this endpoint is one link in.
    [HttpPost("api-keys/{id:int}/revoke")]
    [ProducesResponseType(204)]
    public async Task<IActionResult> Revoke(int id)
    {
        try
        {
            await _apiKeys.RevokeAsync(id);
            return NoContent();
        }
        catch (ApiKeyNotFoundException)
        {
            return NotFound();
        }
    }

    // Deliberately trivial "use this credential" endpoint: any authenticated
    // caller (JWT OR X-Api-Key, see ApiKeyAuthMiddleware) can hit this to prove
    // whichever credential they presented is currently accepted -- this is the
    // "use" step in the create -> use -> revoke -> use sequence for vulnerability
    // #32, since API keys otherwise have no dedicated protected resource of
    // their own to probe against.
    [HttpGet("api-keys/whoami")]
    [ProducesResponseType(200)]
    public IActionResult WhoAmI()
    {
        return Ok(new { authenticated = User.Identity?.IsAuthenticated == true, authType = User.Identity?.AuthenticationType });
    }
}
