using TeamFlow.Core.Entities;

namespace TeamFlow.Infrastructure.Data;

// Auto-seeds on first run -- no separate migration/setup step, matching this
// repo's own fixtures/planted-bug-api convention (zero-setup, just `dotnet run`).
// Every seed password is "Passw0rd!23" so the README's login curl loop can log in
// as all five identities with one shared constant.
public static class DbSeeder
{
    public const string SeedPassword = "Passw0rd!23";

    public static void Seed(TeamFlowDbContext db)
    {
        if (db.Organizations.Any())
        {
            return;
        }

        var acme = new Organization { Name = "Acme Corp", CreditBalance = 250m };
        var globex = new Organization { Name = "Globex Inc", CreditBalance = 100m };
        db.Organizations.AddRange(acme, globex);
        db.SaveChanges();

        string Hash(string plain) => BCrypt.Net.BCrypt.HashPassword(plain);

        var alice = new User { OrganizationId = acme.Id, Email = "alice@acme.test", PasswordHash = Hash(SeedPassword), Role = UserRole.Admin, InternalNotes = "Founder account, do not deactivate." };
        var bob = new User { OrganizationId = acme.Id, Email = "bob@acme.test", PasswordHash = Hash(SeedPassword), Role = UserRole.Manager, InternalNotes = "Escalation contact for on-call." };
        var carol = new User { OrganizationId = acme.Id, Email = "carol@acme.test", PasswordHash = Hash(SeedPassword), Role = UserRole.Member };
        var dave = new User { OrganizationId = globex.Id, Email = "dave@globex.test", PasswordHash = Hash(SeedPassword), Role = UserRole.Admin, InternalNotes = "Globex primary billing contact." };
        var erin = new User { OrganizationId = globex.Id, Email = "erin@globex.test", PasswordHash = Hash(SeedPassword), Role = UserRole.Member };
        db.Users.AddRange(alice, bob, carol, dave, erin);
        db.SaveChanges();

        var acmeProject = new Project { OrganizationId = acme.Id, Name = "Website Relaunch", Description = "Q3 marketing site refresh." };
        var acmeProject2 = new Project { OrganizationId = acme.Id, Name = "Internal Tooling", Description = "Ops dashboards and scripts." };
        var globexProject = new Project { OrganizationId = globex.Id, Name = "Payments Migration", Description = "Move billing to the new provider." };
        db.Projects.AddRange(acmeProject, acmeProject2, globexProject);
        db.SaveChanges();

        db.ProjectTasks.AddRange(
            new ProjectTask { ProjectId = acmeProject.Id, Title = "Draft homepage copy", Description = "First pass on hero + pricing sections.", Status = ProjectTaskStatus.InProgress, AssignedUserId = carol.Id },
            new ProjectTask { ProjectId = acmeProject.Id, Title = "Set up staging environment", Description = "Mirror prod config for QA.", Status = ProjectTaskStatus.Todo, AssignedUserId = bob.Id },
            new ProjectTask { ProjectId = acmeProject2.Id, Title = "Automate nightly backups", Description = "Cron job + S3-compatible storage.", Status = ProjectTaskStatus.Done, AssignedUserId = bob.Id },
            new ProjectTask { ProjectId = globexProject.Id, Title = "Audit legacy invoices", Description = "Reconcile against the old provider's export.", Status = ProjectTaskStatus.InProgress, AssignedUserId = erin.Id }
        );
        db.SaveChanges();

        db.Documents.Add(new Document
        {
            ProjectId = acmeProject.Id,
            FileName = "brand-guidelines.pdf",
            StoragePath = "brand-guidelines.pdf",
            ContentType = "application/pdf",
            UploadedByUserId = alice.Id,
        });
        db.SaveChanges();
    }
}
