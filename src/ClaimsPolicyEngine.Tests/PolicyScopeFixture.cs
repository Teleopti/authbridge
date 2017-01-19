using NUnit.Framework;

namespace ClaimsPolicyEngine.Tests
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using Exceptions;
    using Model;

	public class PolicyScopeFixture
    {
        private static readonly ClaimType sampleClaimType = new ClaimType("http://tests/sampleclaimtype/", "sampleclaimtype");
        private static readonly Issuer sampleIssuer = new Issuer("http://sampleissuer", "SampleIssuer");

        [Test]
        public void AddRuleShouldAddNewPolicyRuleToTheScope()
        {
            var scope = RetrievePolicyScope();
            var rule = new PolicyRule(AssertionsMatch.Any, GetSampleInputClaims(), GetSampleOutputClaim());

            Assert.AreEqual(0, scope.Rules.Count);

            scope.AddRule(rule);

            Assert.AreEqual(1, scope.Rules.Count);
            Assert.AreSame(rule, scope.Rules[0]);
        }

        [Test]
        public void AddRuleShouldAddClaimTypeIfDoesNotExists()
        {
            var scope = RetrievePolicyScope();
            var claimFullName = "http://tests/newsampleclaimtype/";
            var inputClaim = new InputPolicyClaim(sampleIssuer, new ClaimType(claimFullName, string.Empty), "new sample value");
            var rule = new PolicyRule(AssertionsMatch.Any, new List<InputPolicyClaim> { inputClaim }, GetSampleOutputClaim());

            Assert.AreEqual(1, scope.ClaimTypes.Count);

            scope.AddRule(rule);

            Assert.AreEqual(2, scope.ClaimTypes.Count);

            var result = scope.ClaimTypes.ElementAt(1);

            Assert.AreEqual(claimFullName, result.FullName);
            Assert.AreEqual("newsampleclaimtype", result.DisplayName);
        }

        [Test]
        public void AddRuleShouldSetTheRightClaimTypeDisplayName()
        {
            var scope = RetrievePolicyScope();
            var inputClaimType = new ClaimType("http://tests/sampleclaimtype/", string.Empty);

            var inputClaim = new InputPolicyClaim(sampleIssuer, inputClaimType, "new sample value");
            var rule = new PolicyRule(AssertionsMatch.Any, new List<InputPolicyClaim> { inputClaim }, GetSampleOutputClaim());

            Assert.AreEqual(string.Empty, inputClaimType.DisplayName);
            Assert.AreEqual(1, scope.ClaimTypes.Count);

            scope.AddRule(rule);

            Assert.AreEqual(sampleClaimType.DisplayName, inputClaimType.DisplayName);
            Assert.AreEqual(1, scope.ClaimTypes.Count);
        }

        [Test]
        public void AddRuleShouldAddClaimTypeIfDoesNotExistsWithAnUniqueDisplayName()
        {
            var scope = RetrievePolicyScope();
            var claimFullName = "http://tests/newsampleclaimtype/";

            // The DisplayName is repeated but the FullName is unique
            var inputClaim = new InputPolicyClaim(sampleIssuer, new ClaimType(claimFullName, "sampleclaimtype"), "new sample value");
            var rule = new PolicyRule(AssertionsMatch.Any, new List<InputPolicyClaim> { inputClaim }, GetSampleOutputClaim());

            Assert.AreEqual(1, scope.ClaimTypes.Count);

            scope.AddRule(rule);

            Assert.AreEqual(2, scope.ClaimTypes.Count);

            var result = scope.ClaimTypes.ElementAt(1);

            Assert.AreEqual(claimFullName, result.FullName);
            Assert.AreEqual("newsampleclaimtype", result.DisplayName);
        }

        [Test]
        public void AddRuleThrowsIfIssuerOfInputClaimDoesNotExists()
        {
            var scope = RetrievePolicyScope();
            var newIssuer = new Issuer("http://newsampleissuer");
            var inputClaim = new InputPolicyClaim(newIssuer, sampleClaimType, "sample value");
            var rule = new PolicyRule(AssertionsMatch.Any, new List<InputPolicyClaim> { inputClaim }, GetSampleOutputClaim());

            Assert.Throws<PolicyScopeException>(()=>scope.AddRule(rule), "The issuer 'http://newsampleissuer' was not found on the issuers section of the scope.");
        }

        [Test]
        public void AddRuleThrowsIfIssuerOfInputClaimIsNull()
		{
			var scope = RetrievePolicyScope();
			var inputClaim = new InputPolicyClaim(null, sampleClaimType, "sample value");
			var rule = new PolicyRule(AssertionsMatch.Any, new List<InputPolicyClaim> { inputClaim }, GetSampleOutputClaim());

			Assert.Throws<ArgumentException>(() => scope.AddRule(rule), "The Issuer property of the Claim cannot be null.");
        }

        [Test]
        public void AddRuleDoesNotAddPolicyRuleIfAlreadyExists()
        {
            var scope = RetrievePolicyScope();
            var orginalRule = new PolicyRule(AssertionsMatch.Any, GetSampleInputClaims(), GetSampleOutputClaim());

            Assert.AreEqual(0, scope.Rules.Count);

            scope.AddRule(orginalRule);

            Assert.AreEqual(1, scope.Rules.Count);
            Assert.AreSame(orginalRule, scope.Rules[0]);

            var copyRule = new PolicyRule(AssertionsMatch.Any, GetSampleInputClaims(), GetSampleOutputClaim());

            scope.AddRule(orginalRule);

            Assert.AreEqual(1, scope.Rules.Count);
            Assert.AreSame(orginalRule, scope.Rules[0]);
        }

        private static OutputPolicyClaim GetSampleOutputClaim()
        {
            return new OutputPolicyClaim(sampleClaimType, "other sample value");
        }

        private static IEnumerable<InputPolicyClaim> GetSampleInputClaims()
        {
            var inputClaims = new List<InputPolicyClaim>
                {
                    new InputPolicyClaim(sampleIssuer, sampleClaimType, "sample value 1"),
                    new InputPolicyClaim(sampleIssuer, sampleClaimType, "sample value 2")
                };

            return inputClaims;
        }

        private static PolicyScope RetrievePolicyScope()
        {
            var scope = new PolicyScope(new Uri("http://localhost/tests"));

            scope.ClaimTypes.Add(sampleClaimType);
            scope.Issuers.Add(sampleIssuer);

            return scope;
        }
    }
}
