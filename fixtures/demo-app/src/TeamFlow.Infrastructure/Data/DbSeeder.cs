using TeamFlow.Core.Entities;

namespace TeamFlow.Infrastructure.Data;

// Auto-seeds on first run -- no separate migration/setup step, matching this
// repo's own fixtures/planted-bug-api convention (zero-setup, just `dotnet run`).
// Every seed password is "Passw0rd!23" so the README's login curl loop can log in
// as all identities with one shared constant.
//
// The original 5 identities (alice/bob/carol@acme.test, dave/erin@globex.test)
// and their ids/roles/org ids are preserved exactly as they always were --
// auth.identities.example.json and the README's curl examples reference them
// by name. Everything below that block is new volume: 2 more organizations,
// many more users/teams/projects/tasks, and seed data for every new entity
// (invitations, comments, notifications, API keys, subscriptions) so the app
// is a realistic-scale fuzzing target, not just a handful of illustrative rows.
public static class DbSeeder
{
    public const string SeedPassword = "Passw0rd!23";

    public static void Seed(TeamFlowDbContext db)
    {
        if (db.Organizations.Any())
        {
            return;
        }

        string Hash(string plain) => BCrypt.Net.BCrypt.HashPassword(plain);

        // ── Original seed (unchanged) ──────────────────────────────────────
        var acme = new Organization { Name = "Acme Corp", CreditBalance = 250m };
        var globex = new Organization { Name = "Globex Inc", CreditBalance = 100m };
        db.Organizations.AddRange(acme, globex);
        db.SaveChanges();

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

        // ── New volume ──────────────────────────────────────────────────────
        var rng = new Random(20260728); // fixed seed: every fresh clone gets identical data

        var taskTitles = new[]
        {
            "Fix flaky integration test", "Write API documentation", "Upgrade dependency versions",
            "Investigate memory leak", "Design onboarding flow", "Add retry logic to worker queue",
            "Migrate config to environment variables", "Improve error messages", "Add pagination to list endpoint",
            "Refactor authentication middleware", "Set up monitoring alerts", "Clean up unused feature flags",
        };
        var taskDescriptions = new[]
        {
            "Follow-up from last sprint retro.",
            "Blocked on design review, escalate if no response by Friday.",
            "Low priority but easy win.",
            "Customer-reported issue, see support ticket for repro steps.",
            "Needed before next release cut.",
            null,
        };

        // 2 more organizations, each with 6 users (1 Admin, 1 Manager, 4 Member),
        // 2 teams, 3 projects, 6 tasks/project, comments, notifications,
        // invitations, API keys, and a subscription -- plus the same shape
        // retrofitted onto Acme/Globex above so every organization in the
        // dataset is equally rich, not just the two new ones.
        var orgDefs = new (string name, decimal credits, string domain)[]
        {
            ("Initech LLC", 500m, "initech.test"),
            ("Umbrella Group", 750m, "umbrella.test"),
        };

        var allOrgs = new List<Organization> { acme, globex };
        var usersByOrg = new Dictionary<int, List<User>>
        {
            [acme.Id] = new() { alice, bob, carol },
            [globex.Id] = new() { dave, erin },
        };
        var projectsByOrg = new Dictionary<int, List<Project>>
        {
            [acme.Id] = new() { acmeProject, acmeProject2 },
            [globex.Id] = new() { globexProject },
        };

        foreach (var (name, credits, domain) in orgDefs)
        {
            var org = new Organization { Name = name, CreditBalance = credits };
            db.Organizations.Add(org);
            db.SaveChanges();
            allOrgs.Add(org);

            var admin = new User { OrganizationId = org.Id, Email = $"admin@{domain}", PasswordHash = Hash(SeedPassword), Role = UserRole.Admin, InternalNotes = $"{name} primary admin." };
            var manager = new User { OrganizationId = org.Id, Email = $"manager@{domain}", PasswordHash = Hash(SeedPassword), Role = UserRole.Manager };
            var members = Enumerable.Range(1, 4)
                .Select(i => new User { OrganizationId = org.Id, Email = $"member{i}@{domain}", PasswordHash = Hash(SeedPassword), Role = UserRole.Member })
                .ToList();
            var orgUsers = new List<User> { admin, manager };
            orgUsers.AddRange(members);
            db.Users.AddRange(orgUsers);
            db.SaveChanges();
            usersByOrg[org.Id] = orgUsers;

            var projects = new List<Project>
            {
                new() { OrganizationId = org.Id, Name = "Platform Migration", Description = $"Move {name}'s core services to the new platform." },
                new() { OrganizationId = org.Id, Name = "Customer Portal Revamp", Description = "Self-service dashboard for external customers." },
                new() { OrganizationId = org.Id, Name = "Q4 Compliance Review", Description = "Annual audit prep and remediation tracking." },
            };
            db.Projects.AddRange(projects);
            db.SaveChanges();
            projectsByOrg[org.Id] = projects;
        }

        // Teams + memberships for every organization (including the original two).
        foreach (var org in allOrgs)
        {
            var orgUsers = usersByOrg[org.Id];
            var engineering = new Team { OrganizationId = org.Id, Name = "Engineering" };
            var design = new Team { OrganizationId = org.Id, Name = "Design" };
            db.Teams.AddRange(engineering, design);
            db.SaveChanges();

            for (var i = 0; i < orgUsers.Count; i++)
            {
                var team = i % 2 == 0 ? engineering : design;
                var role = i == 0 ? TeamRole.Lead : TeamRole.Member;
                db.TeamMemberships.Add(new TeamMembership { TeamId = team.Id, UserId = orgUsers[i].Id, Role = role });
            }
            db.SaveChanges();
        }

        // 6 more tasks per project (every project in every org, including the
        // original three), each with 0-2 comments and evenly spread across
        // Todo/InProgress/Done so list/search/stats endpoints have real
        // variety to return.
        var allTasks = new List<ProjectTask>(db.ProjectTasks);
        foreach (var org in allOrgs)
        {
            var orgUsers = usersByOrg[org.Id];
            foreach (var project in projectsByOrg[org.Id])
            {
                for (var i = 0; i < 6; i++)
                {
                    var status = (ProjectTaskStatus)(i % 3 == 0 ? ProjectTaskStatus.Todo : i % 3 == 1 ? ProjectTaskStatus.InProgress : ProjectTaskStatus.Done);
                    var task = new ProjectTask
                    {
                        ProjectId = project.Id,
                        Title = taskTitles[rng.Next(taskTitles.Length)],
                        Description = taskDescriptions[rng.Next(taskDescriptions.Length)],
                        Status = status,
                        AssignedUserId = orgUsers[rng.Next(orgUsers.Count)].Id,
                    };
                    db.ProjectTasks.Add(task);
                    allTasks.Add(task);
                }
            }
        }
        db.SaveChanges();

        // Comments: 0-2 on roughly two thirds of all tasks (original four
        // included), authored by a random member of the task's own organization.
        var projectOrgLookup = allOrgs.SelectMany(o => projectsByOrg[o.Id].Select(p => (p.Id, o.Id))).ToDictionary(x => x.Item1, x => x.Item2);
        foreach (var task in allTasks)
        {
            if (!projectOrgLookup.TryGetValue(task.ProjectId, out var orgId))
            {
                continue;
            }
            if (rng.NextDouble() > 0.65)
            {
                continue;
            }
            var orgUsers = usersByOrg[orgId];
            var commentCount = rng.Next(1, 3);
            for (var c = 0; c < commentCount; c++)
            {
                db.Comments.Add(new Comment
                {
                    TaskId = task.Id,
                    AuthorUserId = orgUsers[rng.Next(orgUsers.Count)].Id,
                    Body = c == 0 ? "Started looking into this." : "Any update on this one?",
                });
            }
        }
        db.SaveChanges();

        // Notifications: 2-4 per user for every user in the dataset.
        var notificationTemplates = new (string type, string message)[]
        {
            ("task_assigned", "You were assigned a new task."),
            ("comment_added", "Someone commented on your task."),
            ("invitation_sent", "An invitation was sent on your behalf."),
            ("task_approved", "Your submitted task was approved."),
        };
        foreach (var org in allOrgs)
        {
            foreach (var user in usersByOrg[org.Id])
            {
                var count = rng.Next(2, 5);
                for (var i = 0; i < count; i++)
                {
                    var (type, message) = notificationTemplates[rng.Next(notificationTemplates.Length)];
                    db.Notifications.Add(new Notification
                    {
                        UserId = user.Id,
                        Type = type,
                        Message = message,
                        ReadAt = i == 0 ? null : DateTime.UtcNow.AddDays(-i), // at least one always unread
                    });
                }
            }
        }
        db.SaveChanges();

        // Invitations: one Pending and one Revoked per organization (Accepted
        // invitations are deliberately not pre-seeded -- accepting one creates
        // a real User row, which only the real /accept endpoint should do, to
        // keep the seed data and the live accept flow from disagreeing about
        // how a User came to exist).
        foreach (var org in allOrgs)
        {
            var inviter = usersByOrg[org.Id][0];
            db.Invitations.Add(new Invitation
            {
                OrganizationId = org.Id,
                Email = $"pending-invite@{org.Name.ToLowerInvariant().Replace(" ", "")}.test",
                Role = UserRole.Member,
                Status = InvitationStatus.Pending,
                InvitedByUserId = inviter.Id,
                Token = Guid.NewGuid().ToString("N"),
            });
            db.Invitations.Add(new Invitation
            {
                OrganizationId = org.Id,
                Email = $"revoked-invite@{org.Name.ToLowerInvariant().Replace(" ", "")}.test",
                Role = UserRole.Member,
                Status = InvitationStatus.Revoked,
                InvitedByUserId = inviter.Id,
                Token = Guid.NewGuid().ToString("N"),
            });
        }
        db.SaveChanges();

        // API keys: one active key for each org's Admin/Manager-equivalent
        // (the first two seeded users of every organization).
        foreach (var org in allOrgs)
        {
            var orgUsers = usersByOrg[org.Id];
            foreach (var user in orgUsers.Take(2))
            {
                var rawKey = "tfk_" + Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(24)).ToLowerInvariant();
                var hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(rawKey)));
                db.ApiKeys.Add(new ApiKey { UserId = user.Id, Label = "seeded-key", KeyHash = hash });
            }
        }
        db.SaveChanges();

        // Subscriptions: one per organization, mixed plans so quota/downgrade
        // endpoints have realistic variety to exercise from the very first run.
        var plans = new[] { SubscriptionPlan.Free, SubscriptionPlan.Pro, SubscriptionPlan.Pro, SubscriptionPlan.Enterprise };
        for (var i = 0; i < allOrgs.Count; i++)
        {
            var plan = plans[i % plans.Length];
            var quota = plan switch { SubscriptionPlan.Free => 5, SubscriptionPlan.Pro => 50, SubscriptionPlan.Enterprise => 1000, _ => 5 };
            db.Subscriptions.Add(new Subscription { OrganizationId = allOrgs[i].Id, Plan = plan, Quota = quota, UsedQuota = rng.Next(0, quota / 2) });
        }
        db.SaveChanges();
    }
}
