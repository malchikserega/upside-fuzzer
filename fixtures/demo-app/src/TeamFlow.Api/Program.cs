using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using TeamFlow.Api.Middleware;
using TeamFlow.Infrastructure.Data;
using TeamFlow.Infrastructure.Services;

var builder = WebApplication.CreateBuilder(args);

var dbPath = Environment.GetEnvironmentVariable("TEAMFLOW_DB_PATH")
    ?? Path.Combine(AppContext.BaseDirectory, "teamflow.db");
var connectionString = $"Data Source={dbPath}";
var storageRoot = Environment.GetEnvironmentVariable("TEAMFLOW_STORAGE_ROOT")
    ?? Path.Combine(AppContext.BaseDirectory, "storage");

// All normal request/response binding uses System.Text.Json (ASP.NET Core's safe
// default). Newtonsoft.Json is used ONLY inside LegacyImportService's manual,
// deliberately-unsafe deserialization call -- never wired into the framework's own
// model-binding pipeline, which would apply it to every endpoint indiscriminately.
builder.Services.AddControllers().AddJsonOptions(opt =>
{
    // Enums as strings ("Admin", not 2) -- both more realistic for a real REST API
    // and what lets grammarc's enum_values-derived boundary mutation actually target
    // meaningful role names instead of opaque integers.
    opt.JsonSerializerOptions.Converters.Add(new System.Text.Json.Serialization.JsonStringEnumConverter());
});
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "TeamFlow API", Version = "v1" });
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT bearer token, e.g. \"Bearer eyJhbGciOi...\"",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer",
    });
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme { Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "Bearer" } },
            Array.Empty<string>()
        },
    });
});

builder.Services.AddDbContext<TeamFlowDbContext>(opt => opt.UseSqlite(connectionString));

builder.Services.AddScoped<AuthService>();
builder.Services.AddSingleton<JwtTokenService>();
builder.Services.AddScoped<CouponService>();
builder.Services.AddScoped<TaskLifecycleService>();
builder.Services.AddScoped<TaskPreviewService>();
builder.Services.AddScoped<LegacyImportService>();
builder.Services.AddScoped<CreditsService>();
builder.Services.AddScoped(_ => new TaskSearchService(connectionString));
builder.Services.AddScoped(sp => new FileStorageService(sp.GetRequiredService<TeamFlowDbContext>(), storageRoot));
builder.Services.AddHttpClient<WebhookService>(); // no domain/IP restriction configured -- see WebhookService's own comment
builder.Services.AddScoped<TeamService>();
builder.Services.AddScoped<InvitationService>();
builder.Services.AddScoped<ApiKeyService>();
builder.Services.AddScoped<PasswordResetService>();
builder.Services.AddScoped<SubscriptionService>();
builder.Services.AddScoped<TaskApprovalService>();
builder.Services.AddScoped<BulkTaskService>();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(opt =>
    {
        opt.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = JwtTokenService.Issuer,
            ValidateAudience = true,
            ValidAudience = JwtTokenService.Issuer,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(JwtTokenService.DemoSigningKey)),
            ValidateLifetime = true,
        };
    });
builder.Services.AddAuthorization();

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<TeamFlowDbContext>();
    db.Database.EnsureCreated();
    DbSeeder.Seed(db);
}

app.UseSwagger();
app.UseSwaggerUI();

app.UseAuthentication();

// Alternate credential path (X-Api-Key), fallback only when JWT didn't already
// authenticate the request -- see TeamFlow.Api/Middleware/ApiKeyAuthMiddleware.cs
// for the full writeup, and ApiKeyService.cs for vulnerability #32 (revoked
// keys can keep working via a stale validation cache).
app.UseMiddleware<ApiKeyAuthMiddleware>();

// Vulnerability #8 (differential auth bypass): a legacy, path-string-based gate
// predating the rest of the API's [Authorize(Roles=...)] model -- see
// TeamFlow.Api/Middleware/LegacyManagerOnlyGateMiddleware.cs for the full writeup.
// Runs AFTER authentication (so it can read the already-validated ClaimsPrincipal)
// but does its own path-based routing decision about which paths need which role,
// independent of -- and with a real gap relative to -- the [Authorize] attributes
// used everywhere else in this API.
app.UseMiddleware<LegacyManagerOnlyGateMiddleware>();

app.UseAuthorization();

app.MapControllers();

app.MapGet("/health", () => Results.Ok("ok"));

app.Run();

public partial class Program
{
} // exposed for potential integration tests / clarity
