using UpsideFuzz.Analyzer;

namespace analyzer.Tests;

// Writes small .cs fixture files to a real temp directory (SourceIndex.Load reads
// from disk via Directory.EnumerateFiles, so this mirrors real usage rather than
// hand-building syntax trees) and cleans them up afterward.
internal sealed class TestFixture : IDisposable
{
    public string RootDir { get; }

    public TestFixture(params (string RelativePath, string Content)[] files)
    {
        RootDir = Path.Combine(Path.GetTempPath(), "analyzer-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(RootDir);
        foreach (var (relativePath, content) in files)
        {
            var fullPath = Path.Combine(RootDir, relativePath);
            Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
            File.WriteAllText(fullPath, content);
        }
    }

    public SourceIndex Load()
    {
        var idx = new SourceIndex();
        idx.Load(RootDir);
        return idx;
    }

    public void Dispose()
    {
        try { Directory.Delete(RootDir, recursive: true); } catch { /* best-effort cleanup */ }
    }
}
