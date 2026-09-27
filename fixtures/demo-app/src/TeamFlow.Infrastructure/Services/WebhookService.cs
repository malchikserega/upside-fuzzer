using Microsoft.EntityFrameworkCore;
using TeamFlow.Core.Entities;
using TeamFlow.Infrastructure.Data;

namespace TeamFlow.Infrastructure.Services;

public class WebhookService
{
    private readonly TeamFlowDbContext _db;
    private readonly HttpClient _http;

    public WebhookService(TeamFlowDbContext db, HttpClient http)
    {
        _db = db;
        _http = http;
    }

    // Vulnerability #19 (SSRF): "validate the webhook is reachable before saving it"
    // is a real, common feature -- and a real, common way SSRF gets introduced. No
    // allowlist, no blocklist of link-local/metadata addresses, no restriction on
    // scheme or port: the server fetches whatever URL the caller supplies and
    // reflects status/body back, from inside the container's own network context.
    //
    // void/go/mutations.go's ssrf payload category specifically targets the three
    // real cloud-metadata addresses (169.254.169.254, metadata.google.internal,
    // 100.100.100.200) -- which only resolve to anything meaningful when this app
    // actually runs inside a real cloud VM. For local verification without a cloud
    // environment, see README.md's "Verifying SSRF locally" section, which uses
    // TeamFlow.Api's own /api/internal/aws-metadata-stub endpoint (a local stand-in
    // that mimics the shape of a real AWS IMDS response) and shows how to seed it
    // into dict.custom.json so the fuzzer's own dictionary tries it too.
    public async Task<(int statusCode, string bodySnippet)> TestAsync(int organizationId, string url)
    {
        _ = await _db.Organizations.FirstOrDefaultAsync(o => o.Id == organizationId)
            ?? throw new KeyNotFoundException("Organization not found.");

        using var response = await _http.GetAsync(url);
        var body = await response.Content.ReadAsStringAsync();
        var snippet = body.Length > 2048 ? body[..2048] : body;
        return ((int)response.StatusCode, snippet);
    }

    public async Task<Webhook> SaveAsync(int organizationId, string url)
    {
        var webhook = new Webhook { OrganizationId = organizationId, Url = url, Secret = Guid.NewGuid().ToString("N") };
        _db.Webhooks.Add(webhook);
        await _db.SaveChangesAsync();
        return webhook;
    }
}
