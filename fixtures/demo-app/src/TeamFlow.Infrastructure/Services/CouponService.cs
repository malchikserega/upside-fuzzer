using Microsoft.EntityFrameworkCore;
using TeamFlow.Infrastructure.Data;

namespace TeamFlow.Infrastructure.Services;

public class CouponRedeemException : Exception
{
    public CouponRedeemException(string message) : base(message)
    {
    }
}

public class CouponService
{
    private readonly TeamFlowDbContext _db;

    public CouponService(TeamFlowDbContext db)
    {
        _db = db;
    }

    // ── Vulnerability #20: coverage-guided-only, findable via ConstantExtractor/CmpLog ──
    //
    // This 19-character internal QA bypass code is not documented anywhere a client
    // could discover it, and a black-box fuzzer randomly mutating the `code` field
    // has effectively zero probability of ever generating it by chance (26^19-ish
    // search space for letters alone). It only becomes discoverable because it is a
    // literal string constant sitting in the compiled IL of this exact comparison:
    //   - dotnet/instrumentor/Program.cs::ConstantExtractor harvests it directly out of the
    //     IL at instrument time -- no execution required at all -- and feeds it back
    //     into void/go/mutation_engine.go's mutateStringCategorized candidate pool.
    //   - CmpLog (dotnet/instrumentor/Program.cs::CmpLogInstrumentor) would also recover it
    //     live, the first time *any* string gets compared against it, by recording
    //     the actual operand of the String.Equals/op_Equality call.
    // Either mechanism turns an unguessable secret into a few-KB dictionary entry;
    // neither exists in a black-box fuzzer with no access to the target's own binary.
    //
    // The comparison lives in its own plain, non-async method deliberately: the
    // instrumentor always excludes compiler-generated async state-machine types
    // (`<Method>d__N`, see dotnet/instrumentor/Program.cs's `d__` check and docs/ARCHITECTURE.md
    // section 3) from every IL pass, coverage probes and ConstantExtractor/CmpLog
    // alike, so a comparison written directly inside `async Task RedeemAsync(...)`
    // would be invisible to both mechanisms. Pulling it out into an ordinary method
    // on the class keeps it in CouponService's own IL, where it's actually seen.
    private const string InternalQaBypassCode = "QA-INTERNAL-BYPASS-58f3";

    private static bool IsBackdoorCode(string code) => code == InternalQaBypassCode;

    public async Task<decimal> RedeemAsync(int organizationId, string code)
    {
        var org = await _db.Organizations.FirstOrDefaultAsync(o => o.Id == organizationId)
            ?? throw new CouponRedeemException("Organization not found.");

        if (IsBackdoorCode(code))
        {
            // The backdoor grants a credit far outside any balance this org could
            // reach organically -- immediately followed by an operation that
            // assumes balances stay in a sane range. 5e17 * 100 comfortably fits in
            // a decimal (max ~7.9e28) but overflows a long (max ~9.2e18) once cast,
            // and decimal-to-integral casts in .NET always throw OverflowException
            // on overflow, so this crashes deterministically once the backdoor is used.
            org.CreditBalance += 500_000_000_000_000_000m;
            await _db.SaveChangesAsync();
            var cents = (long)(org.CreditBalance * 100m); // OverflowException here
            return cents;
        }

        // Normal, bounded coupon codes -- a small, fixed, harmless credit.
        var normal = new Dictionary<string, decimal>
        {
            ["WELCOME10"] = 10m,
            ["WELCOME25"] = 25m,
        };
        if (!normal.TryGetValue(code, out var amount))
        {
            throw new CouponRedeemException("Unknown coupon code.");
        }
        org.CreditBalance += amount;
        await _db.SaveChangesAsync();
        return org.CreditBalance;
    }
}
