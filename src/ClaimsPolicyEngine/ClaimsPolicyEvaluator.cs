using System.Security.Claims;

namespace ClaimsPolicyEngine
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Linq;
    using ClaimsPolicyEngine.Exceptions;
    using ClaimsPolicyEngine.Model;
    using ClaimsPolicyEngine.Properties;

    public class ClaimsPolicyEvaluator : IClaimsPolicyEvaluator
    {
        private readonly IPolicyStore store;

        private const string Wildcard = "*";

        public ClaimsPolicyEvaluator(IPolicyStore store)
        {
            if (store == null)
            {
                throw new ArgumentNullException(nameof(store));
            }

            this.store = store;
        }

        public IEnumerable<Claim> Evaluate(Uri scope, IEnumerable<Claim> inputClaims)
        {
            if (scope == null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            if (!inputClaims.Any())
            {
                return Enumerable.Empty<Claim>();
            }

            IEnumerable<PolicyScope> policyScopes = this.store.RetrieveScopes();

            PolicyScope mappingScope = policyScopes.FirstOrDefault(s => s.Uri == scope);
            if (mappingScope == null)
            {
                throw new ClaimsPolicyEvaluationException(string.Format(CultureInfo.CurrentUICulture, Resources.ScopeNotFound, scope));
            }

            return MapClaims(inputClaims, mappingScope);
        }

        private static IEnumerable<Claim> MapClaims(IEnumerable<Claim> inputClaims, PolicyScope mappingScope)
        {
            List<Claim> mappedClaims = new List<Claim>();
            foreach (PolicyRule rule in mappingScope.Rules)
            {
                IEnumerable<Claim> matchingInputClaims = MatchesRule(rule, inputClaims);
                if (matchingInputClaims != null && matchingInputClaims.Any())
                {
                    foreach (var matchingInputClaim in matchingInputClaims)
                    {
                        string outputValue;
                        if (rule.OutputClaim.CopyFromInput)
                        {
                            if (rule.InputClaims.ElementAt(0).Value != Wildcard)
                            {
                                if (rule.OutputClaim.CopyFrom.ToUpperInvariant().Equals(CopyFromConstants.InputValue))
                                {
                                    outputValue = rule.InputClaims.ElementAt(0).Value;
                                }
                                else
                                {
                                    outputValue = rule.InputClaims.ElementAt(0).Issuer.DisplayName;
                                }
                            }
                            else
                            {
                                if (rule.OutputClaim.CopyFrom.ToUpperInvariant().Equals(CopyFromConstants.InputValue))
                                {
                                    outputValue = matchingInputClaim.Value;
                                }
                                else
                                {
                                    var issuer = mappingScope.Issuers.FirstOrDefault(i => i.Uri == matchingInputClaim.Issuer);

                                    outputValue = issuer != null ? issuer.DisplayName : matchingInputClaim.Issuer;
                                }
                            }
                        }
                        else
                        {
                            outputValue = rule.OutputClaim.Value;
                        }

                        var originalIssuer = mappingScope.Issuers.FirstOrDefault(i => i.Uri == matchingInputClaim.OriginalIssuer);

                        string originalIssuerDisplayName = originalIssuer != null ? originalIssuer.DisplayName : matchingInputClaim.Issuer;

                        mappedClaims.Add(
                            new Claim(
                                rule.OutputClaim.ClaimType.FullName,
                                outputValue,
                                matchingInputClaim.ValueType,
                                matchingInputClaim.Issuer,
                                originalIssuerDisplayName));
                    }
                }
            }

            if (!mappedClaims.Any())
            {
                var claim = inputClaims.SingleOrDefault(x => x.Type == System.IdentityModel.Claims.ClaimTypes.NameIdentifier);
                if (claim != null)
                {
                    mappedClaims.Add(new Claim(
                        ClaimTypes.NameIdentifier,
                        claim.Value,
                        claim.ValueType,
                        claim.Issuer,
                        claim.Issuer));
                }
            }
            return mappedClaims;
        }

        private static IEnumerable<Claim> MatchesRule(PolicyRule rule, IEnumerable<Claim> inputClaims)
        {
            List<Claim> matchingClaims = new List<Claim>();
            foreach (InputPolicyClaim inputPolicyClaim in rule.InputClaims)
            {                
                var claimsMatched = inputClaims.Where(c => (c.Issuer == inputPolicyClaim.Issuer.Uri || c.OriginalIssuer == inputPolicyClaim.Issuer.Uri) 
                                                        && c.Type.Equals(inputPolicyClaim.ClaimType.FullName, StringComparison.OrdinalIgnoreCase)
                                                        && ((inputPolicyClaim.Value == Wildcard) || (c.Value.ToUpperInvariant() == inputPolicyClaim.Value.ToUpperInvariant())));

	            matchingClaims.AddRange(claimsMatched);
            }

            return matchingClaims;
        }
    }
}