using Newtonsoft.Json;
using TeamFlow.Core.Dtos;
using TeamFlow.Core.Entities;
using TeamFlow.Infrastructure.Data;

namespace TeamFlow.Infrastructure.Services;

public class LegacyImportService
{
    private readonly TeamFlowDbContext _db;

    private static readonly JsonSerializerSettings VulnerableSettings = new()
    {
        // Vulnerability #22 (.NET deserialization gadget surface): TypeNameHandling
        // other than None, with no custom SerializationBinder restricting which
        // types may be materialized, is the textbook unsafe Newtonsoft.Json
        // configuration -- a $type-carrying payload can direct the deserializer to
        // instantiate arbitrary types on the classpath. This endpoint predates the
        // rest of the API's System.Text.Json-based (safe-by-default) model binding
        // and was never migrated when the "legacy import" feature was deprecated in
        // favor of the newer /api/projects endpoints -- exactly how this class of
        // bug actually survives in real codebases.
        //
        // void/go/mutations.go's json_dotnet_deser mutation category injects
        // $type-shaped gadget strings (System.IO.FileInfo, System.Diagnostics.Process,
        // etc.) precisely to probe for this configuration. This demo does not wire up
        // a full working gadget chain (that would require a real, weaponizable
        // ysoserial.net-style gadget present on the classpath, which is out of scope
        // for a safe demo) -- what the fuzzer will actually observe here is the
        // deserializer throwing on an unresolvable/invalid $type (a triaged crash,
        // e.g. JsonSerializationException or TypeLoadException), which is exactly
        // what "confirmed the vulnerable configuration is live and reachable" looks
        // like without anyone needing to hand it a working RCE chain.
        TypeNameHandling = TypeNameHandling.Objects,
    };

    public LegacyImportService(TeamFlowDbContext db)
    {
        _db = db;
    }

    public async Task<Project> ImportAsync(int organizationId, string rawJson)
    {
        var payload = JsonConvert.DeserializeObject<LegacyImportPayload>(rawJson, VulnerableSettings)
            ?? throw new InvalidOperationException("Empty legacy import payload.");

        var project = new Project { OrganizationId = organizationId, Name = payload.ProjectName, Description = "Imported from legacy system." };
        _db.Projects.Add(project);
        await _db.SaveChangesAsync();

        foreach (var title in payload.TaskTitles)
        {
            _db.ProjectTasks.Add(new ProjectTask { ProjectId = project.Id, Title = title, Status = ProjectTaskStatus.Todo });
        }
        await _db.SaveChangesAsync();
        return project;
    }
}
