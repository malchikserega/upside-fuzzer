namespace TeamFlow.Core.Dtos;

// Vulnerability #22 (.NET deserialization gadget surface): deserialized by
// TeamFlow.Infrastructure.Services.LegacyImportService using Newtonsoft.Json with
// TypeNameHandling.Objects -- the "legacy import" endpoint predates the rest of the
// API's System.Text.Json-based binding and was never migrated. A $type-carrying
// payload is not bound by ASP.NET's normal (safe) model binder here; it is handed
// directly to JsonConvert.DeserializeObject with unsafe settings.
public class LegacyImportPayload
{
    public string ProjectName { get; set; } = "";
    public List<string> TaskTitles { get; set; } = new();
}
