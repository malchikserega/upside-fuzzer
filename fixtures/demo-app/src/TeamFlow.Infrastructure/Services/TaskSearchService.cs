using Microsoft.Data.Sqlite;

namespace TeamFlow.Infrastructure.Services;

public class TaskSearchService
{
    private readonly string _connectionString;

    public TaskSearchService(string connectionString)
    {
        _connectionString = connectionString;
    }

    // Vulnerability #10 (SQL injection): a raw, string-concatenated ADO.NET query
    // bolted directly onto an otherwise EF-Core-parameterized codebase -- the
    // realistic way SQLi actually gets introduced in the wild (a "quick search
    // feature" reaching for raw SQL "for flexibility", bypassing the ORM's
    // automatic parameterization entirely). `query` is spliced directly into the
    // SQL text with no parameterization and no escaping.
    public List<(int Id, string Title)> Search(int projectId, string query)
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"SELECT Id, Title FROM ProjectTasks WHERE ProjectId = {projectId} AND Title LIKE '%{query}%'"; // <-- the bug
        var results = new List<(int, string)>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            results.Add((reader.GetInt32(0), reader.GetString(1)));
        }
        return results;
    }
}
