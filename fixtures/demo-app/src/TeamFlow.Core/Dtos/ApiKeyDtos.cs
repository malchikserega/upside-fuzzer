using System.ComponentModel.DataAnnotations;

namespace TeamFlow.Core.Dtos;

public class ApiKeyDto
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public string Label { get; set; } = "";
    public bool Revoked { get; set; }
}

// The raw key is only ever returned once, at creation time -- same convention
// real API-key systems use (only the hash is retained server-side).
public class ApiKeyCreatedDto : ApiKeyDto
{
    public string Key { get; set; } = "";
}

public class CreateApiKeyRequest
{
    [Required, StringLength(80, MinimumLength = 1)]
    public string Label { get; set; } = "";
}
