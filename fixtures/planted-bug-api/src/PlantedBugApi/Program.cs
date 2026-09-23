var builder = WebApplication.CreateBuilder(args);
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();
app.UseSwagger();
app.UseSwaggerUI();

app.MapPost("/items", ItemHandlers.CreateItem).WithName("CreateItem");
app.MapGet("/items/{id}", ItemHandlers.GetItemById).WithName("GetItemById");
app.MapGet("/items", ItemHandlers.ListItems).WithName("ListItems");
app.MapGet("/health", () => Results.Ok("ok"));

app.Run();

record Item(int Id, string Name, decimal Price);
record CreateItemRequest(string Name, decimal Price);

// Handlers live on a named, non-lambda class deliberately: SharpFuzz instrumentation
// (dotnet/instrumentor/Program.cs::ShouldInstrument) blanket-excludes any type whose name
// contains "+<>c" (compiler-generated lambda/closure classes) and the synthesized
// top-level-statements "Program" class itself -- a rule that exists to stop
// static-initializer code from firing before the coverage SHM pointer is bound (a real,
// previously-hit production crash, see dotnet/instrumentor/Program.cs's own comment). That
// rule has a real side effect for minimal APIs: it also excludes lambda bodies passed
// directly to app.MapGet/MapPost, since those compile onto exactly those closure/
// Program-nested types -- verified directly against this fixture (0 SHM edges after
// real requests, before this restructuring). Named handler methods on their own class
// avoid the exclusion entirely and are realistic, common style regardless.
static class ItemHandlers
{
    private static readonly List<Item> Items = new();
    private static int _nextId = 1;

    public static IResult CreateItem(CreateItemRequest req)
    {
        var item = new Item(_nextId++, req.Name, req.Price);
        Items.Add(item);
        return Results.Created($"/items/{item.Id}", item);
    }

    public static IResult GetItemById(int id)
    {
        var item = Items.FirstOrDefault(i => i.Id == id);
        return item is null ? Results.NotFound() : Results.Ok(item);
    }

    // Defaults matter here beyond convenience: a bare `GET /items` (no query string) must
    // still execute this method body for bin/verify-hook.sh's generic real-endpoint coverage
    // probe (and any other tool that GETs an endpoint with no a-priori knowledge of its
    // query params) to see real edges. Without defaults, ASP.NET's minimal-API model
    // binding rejects the request with 400 *before* the handler ever runs -- confirmed
    // directly: this fixture showed 0 SHM edges from real traffic before defaults were added.
    public static IResult ListItems(int pageSize = 10, int pageIndex = 0)
    {
        // PLANTED BUG (deliberate, for the E2E regression fixture -- see README.md in
        // this directory): no bounds check on pageSize/pageIndex before slicing. A
        // negative pageSize (or a pageIndex large enough to push the computed count
        // negative) throws ArgumentOutOfRangeException -> unhandled 500, with no
        // dependency on any prior state (works even against an empty list). Mirrors a
        // real bug class this project's own fuzzer found on eShopOnWeb's
        // /api/catalog-items?pageSize=-2.
        var skip = pageIndex * pageSize;
        var count = Math.Min(pageSize, Items.Count - skip);
        var page = Items.GetRange(skip, count);
        return Results.Ok(page);
    }
}
