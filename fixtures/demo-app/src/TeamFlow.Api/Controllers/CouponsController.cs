using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using TeamFlow.Core.Dtos;
using TeamFlow.Infrastructure.Services;

namespace TeamFlow.Api.Controllers;

[ApiController]
[Route("api/organizations/{id:int}/coupons")]
[Authorize]
public class CouponsController : ControllerBase
{
    private readonly CouponService _coupons;

    public CouponsController(CouponService coupons)
    {
        _coupons = coupons;
    }

    // Vulnerability #20 (magic backdoor constant, coverage-guided-only): see
    // CouponService.RedeemAsync's own doc comment.
    [HttpPost("redeem")]
    [ProducesResponseType(200)]
    public async Task<IActionResult> Redeem(int id, CouponRedeemRequest request)
    {
        if (!ModelState.IsValid)
        {
            return ValidationProblem(ModelState);
        }
        try
        {
            var balance = await _coupons.RedeemAsync(id, request.Code);
            return Ok(new { balance });
        }
        catch (CouponRedeemException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }
}
