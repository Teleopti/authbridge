using System.Security.Claims;

namespace SampleRP.Library
{
    using System;
    using System.Linq;
    using System.Security.Principal;
    using System.Threading;

    public static class ClaimHelper
    {
        public static Claim GetCurrentUserClaim(string claimType)
        {
            return GetClaimsFromPrincipal(Thread.CurrentPrincipal, claimType);
        }

        public static Claim GetClaimsFromPrincipal(IPrincipal principal, string claimType)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            ClaimsPrincipal claimsPrincipal = principal as ClaimsPrincipal;

            if (claimsPrincipal == null)
            {
                throw new ArgumentException("Cannot convert principal to IClaimsPrincipal.", nameof(principal));
            }

            return GetClaimFromIdentity(claimsPrincipal.Identities.First(), claimType);
        }

        public static Claim GetClaimFromIdentity(IIdentity identity, string claimType)
        {
            if (identity == null)
            {
                throw new ArgumentNullException(nameof(identity));
            }

            ClaimsIdentity claimsIdentity = identity as ClaimsIdentity;

            if (claimsIdentity == null)
            {
                throw new ArgumentException("Cannot convert identity to IClaimsIdentity", nameof(identity));
            }

            return claimsIdentity.Claims.SingleOrDefault(c => c.Type == claimType);
        }
    }
}