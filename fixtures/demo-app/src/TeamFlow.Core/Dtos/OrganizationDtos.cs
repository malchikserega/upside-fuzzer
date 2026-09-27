using System.ComponentModel.DataAnnotations;

namespace TeamFlow.Core.Dtos;

public class OrganizationDto
{
    public int Id { get; set; }
    public string Name { get; set; } = "";
    public decimal CreditBalance { get; set; }
}

public class CreateProjectRequest
{
    [Required, StringLength(80, MinimumLength = 1)]
    public string Name { get; set; } = "";

    [StringLength(500)]
    public string? Description { get; set; }
}

public class CouponRedeemRequest
{
    [Required, StringLength(64, MinimumLength = 1)]
    public string Code { get; set; } = "";
}

public class CreditsWithdrawRequest
{
    [Range(0.01, 1000000)]
    public decimal Amount { get; set; }
}
