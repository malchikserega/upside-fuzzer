using Microsoft.EntityFrameworkCore;
using TeamFlow.Core.Entities;

namespace TeamFlow.Infrastructure.Data;

public class TeamFlowDbContext : DbContext
{
    public TeamFlowDbContext(DbContextOptions<TeamFlowDbContext> options) : base(options)
    {
    }

    public DbSet<Organization> Organizations => Set<Organization>();
    public DbSet<User> Users => Set<User>();
    public DbSet<Project> Projects => Set<Project>();
    public DbSet<ProjectTask> ProjectTasks => Set<ProjectTask>();
    public DbSet<Document> Documents => Set<Document>();
    public DbSet<Webhook> Webhooks => Set<Webhook>();
    public DbSet<Team> Teams => Set<Team>();
    public DbSet<TeamMembership> TeamMemberships => Set<TeamMembership>();
    public DbSet<Invitation> Invitations => Set<Invitation>();
    public DbSet<Comment> Comments => Set<Comment>();
    public DbSet<Notification> Notifications => Set<Notification>();
    public DbSet<ApiKey> ApiKeys => Set<ApiKey>();
    public DbSet<PasswordResetToken> PasswordResetTokens => Set<PasswordResetToken>();
    public DbSet<Subscription> Subscriptions => Set<Subscription>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<User>().Property(u => u.Role).HasConversion<string>();
        modelBuilder.Entity<ProjectTask>().Property(t => t.Status).HasConversion<string>();
        modelBuilder.Entity<ProjectTask>().Property(t => t.ApprovalStatus).HasConversion<string>();
        modelBuilder.Entity<TeamMembership>().Property(m => m.Role).HasConversion<string>();
        modelBuilder.Entity<Invitation>().Property(i => i.Role).HasConversion<string>();
        modelBuilder.Entity<Invitation>().Property(i => i.Status).HasConversion<string>();
        modelBuilder.Entity<Subscription>().Property(s => s.Plan).HasConversion<string>();
    }
}
