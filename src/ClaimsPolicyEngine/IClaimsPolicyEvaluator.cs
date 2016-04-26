using System.Security.Claims;

namespace ClaimsPolicyEngine
{
    using System;
    using System.Collections.Generic;


    public interface IClaimsPolicyEvaluator
    {
        IEnumerable<Claim> Evaluate(Uri scope, IEnumerable<Claim> inputClaims);
    }
}