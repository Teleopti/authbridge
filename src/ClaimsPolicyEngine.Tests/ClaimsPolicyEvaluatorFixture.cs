using System.Security.Claims;
using NUnit.Framework;

namespace ClaimsPolicyEngine.Tests
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using ClaimsPolicyEngine;
    using Exceptions;
    using Model;
	
    public class ClaimsPolicyEvaluatorFixture
    {
        private readonly ClaimType inputClaimType = new ClaimType("http://myInputClaimType");
        private readonly ClaimType outputClaimType = new ClaimType("http://myOutputClaimType");
        private readonly Issuer issuer = new Issuer("http://myInputClaimIssuer", "6f7051ece706096ac5a05ecb1860e2151c11b491");

        [Test]
        public void ShoudThrowIfInvalidStore()
        {
            Assert.Throws<ArgumentNullException>(() => new ClaimsPolicyEvaluator(null));
        }

        [Test]
        public void ShouldThrowIfInvalidScope()
        {
            ClaimsPolicyEvaluator evaluator = new ClaimsPolicyEvaluator(new MockPolicyStore());

            Assert.Throws<ArgumentNullException>(()=> evaluator.Evaluate(null, new[] { new Claim("http://myInputClaimType", "myInputClaim") }));
        }

        [Test]
        public void ShouldThrowIfScopeIsNotFoundOnStore()
        {
            var store = new MockPolicyStore();
            Issuer issuer = new Issuer("http://myIssuer", "myIssuer");
            ClaimType myClaimType = new ClaimType("http://myClaimType", "myClaimType");
            store.RetrieveScopesReturnValue = 
                new List<PolicyScope>() 
                { 
                    new PolicyScope(
                        new Uri("http://mappedScope"), 
                        new[] { new PolicyRule(AssertionsMatch.All, new[] { new InputPolicyClaim(issuer, myClaimType, "myClaimValue") }, new OutputPolicyClaim(myClaimType, string.Empty, CopyFromConstants.InputValue)) })
                };
            ClaimsPolicyEvaluator evaluator = new ClaimsPolicyEvaluator(store);

            Assert.Throws<ClaimsPolicyEvaluationException>(()=> evaluator.Evaluate(new Uri("http://unmappedScope"), new[] { new Claim("http://myInputClaimType", "myInputClaim") }));
        }

        [Test]
        public void ShouldReturnEmptyOutputCollectionIfInputCollectionIsEmpty()
        {
            ClaimsPolicyEvaluator evaluator = new ClaimsPolicyEvaluator(new MockPolicyStore());

            IEnumerable<Claim> outputClaims = evaluator.Evaluate(new Uri("http://myScope"), new Claim[] { });

            Assert.IsNotNull(outputClaims);
            Assert.AreEqual(0, outputClaims.Count());
        }

        [Test]
        public void ShouldMatchInputClaim()
        {
            var store = new MockPolicyStore();
            ClaimsPolicyEvaluator evaluator = new ClaimsPolicyEvaluator(store);

            InputPolicyClaim inputClaim = new InputPolicyClaim(this.issuer, this.inputClaimType, "myInputClaim");
            OutputPolicyClaim outputClaim = new OutputPolicyClaim(this.outputClaimType, "myOutputClaimValue");
            PolicyRule rule = new PolicyRule(AssertionsMatch.Any, new[] { inputClaim }, outputClaim);

            var policyScope = new PolicyScope(new Uri("http://myScope"), new[] { rule });
            policyScope.AddIssuer(new Issuer("http://originalIssuer", string.Empty, "OriginalIssuer"));
            store.RetrieveScopesReturnValue = new List<PolicyScope>() { policyScope };

            IEnumerable<Claim> evaluatedOutputClaims = evaluator.Evaluate(new Uri("http://myScope"), new[] { new Claim("http://myInputClaimType", "myInputClaim", string.Empty, "http://myInputClaimIssuer", "http://originalIssuer") });

            Assert.IsNotNull(evaluatedOutputClaims);
            Assert.AreEqual(1, evaluatedOutputClaims.Count());
            Assert.AreEqual("http://myOutputClaimType", evaluatedOutputClaims.ElementAt(0).Type);
            Assert.AreEqual("myOutputClaimValue", evaluatedOutputClaims.ElementAt(0).Value);
            Assert.AreEqual("http://myInputClaimIssuer", evaluatedOutputClaims.ElementAt(0).Issuer);
            Assert.AreEqual("OriginalIssuer", evaluatedOutputClaims.ElementAt(0).OriginalIssuer);
        }

        [Test]
        public void ShouldMatchInputClaimWithWildcardOnValue()
        {
            var store = new MockPolicyStore();
            ClaimsPolicyEvaluator evaluator = new ClaimsPolicyEvaluator(store);
           
            InputPolicyClaim inputClaim = new InputPolicyClaim(new Issuer("http://myInputClaimIssuer", "myInputClaimIssuer"), new ClaimType("http://myInputClaimType", "myInputClaimType"), "*");
            OutputPolicyClaim outputClaim = new OutputPolicyClaim(new ClaimType("http://myOutputClaimType", "myOutputClaimType"), "myOutputClaimValue");
            PolicyRule rule = new PolicyRule(AssertionsMatch.Any, new[] { inputClaim }, outputClaim);
            store.RetrieveScopesReturnValue = new List<PolicyScope>() { new PolicyScope(new Uri("http://myScope"), new[] { rule }) };

            IEnumerable<Claim> evaluatedOutputClaims = evaluator.Evaluate(new Uri("http://myScope"), new[] { new Claim("http://myInputClaimType", "anyValueShouldMatch", string.Empty, "http://myInputClaimIssuer") });

            Assert.IsNotNull(evaluatedOutputClaims);
            Assert.AreEqual(1, evaluatedOutputClaims.Count());
            Assert.AreEqual("http://myOutputClaimType", evaluatedOutputClaims.ElementAt(0).Type);
            Assert.AreEqual("myOutputClaimValue", evaluatedOutputClaims.ElementAt(0).Value);
        }

        [Test]
        public void ShouldMatchInputClaimValueInCaseInsensitiveFashion()
        {
            var store = new MockPolicyStore();
            var scopeUri = new Uri("http://myScope");
            var inputClaimValue = "myInputClaimValue";
            var outputClaimValue = "myOutputClaimValue";
            
            InputPolicyClaim inputClaim = new InputPolicyClaim(
                new Issuer("http://myInputClaimIssuer", "myInputClaimIssuer"),
                new ClaimType("http://myInputClaimType", "myInputClaimType"),
                inputClaimValue);
            OutputPolicyClaim outputClaim = new OutputPolicyClaim(
                new ClaimType("http://myOutputClaimType", "myOutputClaimType"),
                outputClaimValue);
            PolicyRule rule = new PolicyRule(AssertionsMatch.Any, new[] { inputClaim }, outputClaim);
            store.RetrieveScopesReturnValue = new List<PolicyScope> { new PolicyScope(scopeUri, new[] { rule }) };

            var evaluator = new ClaimsPolicyEvaluator(store);
            var evaluatedOutputClaims = evaluator.Evaluate(scopeUri, new[] { new Claim("http://myInputClaimType", inputClaimValue.ToUpperInvariant(), string.Empty, "http://myInputClaimIssuer") });

            Assert.IsNotNull(evaluatedOutputClaims);
            Assert.AreEqual(1, evaluatedOutputClaims.Count());
            Assert.AreEqual(outputClaimValue, evaluatedOutputClaims.ElementAt(0).Value);
        }

        [Test]
        public void ShouldMatchInputClaimAndCopyInputValueToOutputValueWithWildcard()
        {
            var store = new MockPolicyStore();
            ClaimsPolicyEvaluator evaluator = new ClaimsPolicyEvaluator(store);

            ClaimType inputClaimType = new ClaimType("http://myInputClaimType");
            ClaimType outputClaimType = new ClaimType("http://myOutputClaimType");
            Issuer issuer = new Issuer("http://myInputClaimIssuer");

            InputPolicyClaim inputClaim = new InputPolicyClaim(issuer, inputClaimType, "*");
            OutputPolicyClaim outputClaim = new OutputPolicyClaim(outputClaimType, string.Empty, CopyFromConstants.InputValue);
            PolicyRule rule = new PolicyRule(AssertionsMatch.Any, new[] { inputClaim }, outputClaim);
            store.RetrieveScopesReturnValue = new List<PolicyScope>() { new PolicyScope(new Uri("http://myScope"), new[] { rule }) };

            IEnumerable<Claim> evaluatedOutputClaims = evaluator.Evaluate(new Uri("http://myScope"), new[] { new Claim("http://myInputClaimType", "myInputClaimValue", string.Empty, "http://myInputClaimIssuer") });

            Assert.IsNotNull(evaluatedOutputClaims);
            Assert.AreEqual(1, evaluatedOutputClaims.Count());
            Assert.AreEqual("http://myOutputClaimType", evaluatedOutputClaims.ElementAt(0).Type);
            Assert.AreEqual("myInputClaimValue", evaluatedOutputClaims.ElementAt(0).Value);
        }

        [Test]
        public void ShouldMatchInputClaimAndCopyInputValueToOutputValue()
        {
            var store = new MockPolicyStore();
            ClaimsPolicyEvaluator evaluator = new ClaimsPolicyEvaluator(store);

            ClaimType inputClaimType = new ClaimType("http://myInputClaimType");
            ClaimType outputClaimType = new ClaimType("http://myOutputClaimType");
            Issuer issuer = new Issuer("http://myInputClaimIssuer");

            InputPolicyClaim inputClaim = new InputPolicyClaim(issuer, inputClaimType, "myInputClaimValue");
            OutputPolicyClaim outputClaim = new OutputPolicyClaim(outputClaimType, string.Empty, CopyFromConstants.InputValue);
            PolicyRule rule = new PolicyRule(AssertionsMatch.Any, new[] { inputClaim }, outputClaim);
            store.RetrieveScopesReturnValue = new List<PolicyScope>() { new PolicyScope(new Uri("http://myScope"), new[] { rule }) };

            IEnumerable<Claim> evaluatedOutputClaims = evaluator.Evaluate(new Uri("http://myScope"), new[] { new Claim("http://myInputClaimType", "myInputClaimValue", string.Empty, "http://myInputClaimIssuer") });

            Assert.IsNotNull(evaluatedOutputClaims);
            Assert.AreEqual(1, evaluatedOutputClaims.Count());
            Assert.AreEqual("http://myOutputClaimType", evaluatedOutputClaims.ElementAt(0).Type);
            Assert.AreEqual("myInputClaimValue", evaluatedOutputClaims.ElementAt(0).Value);
        }

        [Test]
        public void ShouldMatchInputClaimAndCopyInputIssuerToOutputValue()
        {
            var store = new MockPolicyStore();
            ClaimsPolicyEvaluator evaluator = new ClaimsPolicyEvaluator(store);

            ClaimType inputClaimType = new ClaimType("http://myInputClaimType");
            ClaimType outputClaimType = new ClaimType("http://myOutputClaimType");
            Issuer issuer = new Issuer("http://myInputClaimIssuer");

            InputPolicyClaim inputClaim = new InputPolicyClaim(issuer, inputClaimType, "myInputClaim");
            OutputPolicyClaim outputClaim = new OutputPolicyClaim(outputClaimType, string.Empty, CopyFromConstants.InputIssuer);
            PolicyRule rule = new PolicyRule(AssertionsMatch.Any, new[] { inputClaim }, outputClaim);
            store.RetrieveScopesReturnValue = new List<PolicyScope>() { new PolicyScope(new Uri("http://myScope"), new[] { rule }) };

            IEnumerable<Claim> evaluatedOutputClaims = evaluator.Evaluate(new Uri("http://myScope"), new[] { new Claim("http://myInputClaimType", "myInputClaim", string.Empty, "http://myInputClaimIssuer") });

            Assert.IsNotNull(evaluatedOutputClaims);
            Assert.AreEqual(1, evaluatedOutputClaims.Count());
            Assert.AreEqual("http://myOutputClaimType", evaluatedOutputClaims.ElementAt(0).Type);
            Assert.AreEqual("http://myInputClaimIssuer", evaluatedOutputClaims.ElementAt(0).Value);
        }

        [Test]
        public void ShouldNotMatchInputClaimWithDifferentClaimType()
        {
            var store = new MockPolicyStore();
            ClaimsPolicyEvaluator evaluator = new ClaimsPolicyEvaluator(store);

            InputPolicyClaim inputClaim = new InputPolicyClaim(this.issuer, this.inputClaimType, "myInputClaim");
            OutputPolicyClaim outputClaim = new OutputPolicyClaim(this.outputClaimType, "theValue");
            PolicyRule rule = new PolicyRule(AssertionsMatch.Any, new[] { inputClaim }, outputClaim);
            store.RetrieveScopesReturnValue = new List<PolicyScope>() { new PolicyScope(new Uri("http://myScope"), new[] { rule }) };

            IEnumerable<Claim> evaluatedOutputClaims = evaluator.Evaluate(new Uri("http://myScope"), new[] { new Claim("http://otherInputClaimType", "myInputClaim", string.Empty, "http://myInputClaimIssuer") });

            Assert.IsNotNull(evaluatedOutputClaims);
            Assert.AreEqual(0, evaluatedOutputClaims.Count());
        }

        [Test]
        public void ShouldNotMatchInputClaimWithDifferentIssuer()
        {
            var store = new MockPolicyStore();
            ClaimsPolicyEvaluator evaluator = new ClaimsPolicyEvaluator(store);

            InputPolicyClaim inputClaim = new InputPolicyClaim(this.issuer, this.inputClaimType, "myInputClaim");
            OutputPolicyClaim outputClaim = new OutputPolicyClaim(this.outputClaimType, "myOutputClaimValue");
            PolicyRule rule = new PolicyRule(AssertionsMatch.Any, new[] { inputClaim }, outputClaim);
            store.RetrieveScopesReturnValue = new List<PolicyScope>() { new PolicyScope(new Uri("http://myScope"), new[] { rule }) };

            IEnumerable<Claim> evaluatedOutputClaims = evaluator.Evaluate(new Uri("http://myScope"), new[] { new Claim("http://myInputClaimType", "myInputClaim", string.Empty, "http://otherInputClaimIssuer") });

            Assert.IsNotNull(evaluatedOutputClaims);
            Assert.AreEqual(0, evaluatedOutputClaims.Count());
        }

        [Test]
        public void ShouldNotMatchInputClaimWithDifferentValue()
        {
            var store = new MockPolicyStore();
            ClaimsPolicyEvaluator evaluator = new ClaimsPolicyEvaluator(store);

            InputPolicyClaim inputClaim = new InputPolicyClaim(this.issuer, this.inputClaimType, "myInputClaim");
            OutputPolicyClaim outputClaim = new OutputPolicyClaim(this.outputClaimType, "myOutputClaimValue");
            PolicyRule rule = new PolicyRule(AssertionsMatch.Any, new[] { inputClaim }, outputClaim);
            store.RetrieveScopesReturnValue = new List<PolicyScope> { new PolicyScope(new Uri("http://myScope"), new[] { rule }) };

            IEnumerable<Claim> evaluatedOutputClaims = evaluator.Evaluate(new Uri("http://myScope"), new[] { new Claim("http://myInputClaimType", "otherInputClaim", string.Empty, "http://myInputClaimIssuer") });

            Assert.IsNotNull(evaluatedOutputClaims);
            Assert.AreEqual(0, evaluatedOutputClaims.Count());
        }

        [Test]
        public void ShouldOutputCorrectInputValue()
        {
            var store = new MockPolicyStore();
            ClaimsPolicyEvaluator evaluator = new ClaimsPolicyEvaluator(store);
            InputPolicyClaim inputPolicyClaim1 = new InputPolicyClaim(this.issuer, this.inputClaimType, "*");

            ClaimType outputClaimType1 = new ClaimType("http://myOutputClaimType1");
            OutputPolicyClaim outputPolicyClaim1 = new OutputPolicyClaim(outputClaimType1, "myOutputClaimValue");

            PolicyRule policyRule1 = new PolicyRule(AssertionsMatch.Any, new[] { inputPolicyClaim1 }, outputPolicyClaim1);

            InputPolicyClaim inputPolicyClaim2 = new InputPolicyClaim(this.issuer, this.inputClaimType, "inputClaimValue");

            ClaimType outputClaimType2 = new ClaimType("http://myOutputClaimType2");
            OutputPolicyClaim outputPolicyClaim2 = new OutputPolicyClaim(outputClaimType2, string.Empty, CopyFromConstants.InputValue);
            PolicyRule policyRule2 = new PolicyRule(AssertionsMatch.Any, new[] { inputPolicyClaim2 }, outputPolicyClaim2);
            store.RetrieveScopesReturnValue = new List<PolicyScope>() { new PolicyScope(new Uri("http://myScope"), new[] { policyRule1, policyRule2 }) };

            IEnumerable<Claim> evaluatedOutputClaims = evaluator.Evaluate(new Uri("http://myScope"), new[] { new Claim("http://myInputClaimType", "inputClaimValue", string.Empty, "http://myInputClaimIssuer") });

            Assert.IsNotNull(evaluatedOutputClaims);
            Assert.AreEqual(2, evaluatedOutputClaims.Count());
            var outputClaim1 = evaluatedOutputClaims.FirstOrDefault(c => c.Type == "http://myOutputClaimType1");
            Assert.IsNotNull(outputClaim1);
            Assert.AreEqual("myOutputClaimValue", outputClaim1.Value);
            var outputClaim2 = evaluatedOutputClaims.FirstOrDefault(c => c.Type == "http://myOutputClaimType2");
            Assert.IsNotNull(outputClaim2);
            Assert.AreEqual("inputClaimValue", outputClaim2.Value);
        }

        [Test]
        public void ShoudMatchInputClaimWithAssertionMatchAll()
        {
            var store = new MockPolicyStore();
            ClaimsPolicyEvaluator evaluator = new ClaimsPolicyEvaluator(store);

            InputPolicyClaim inputClaim = new InputPolicyClaim(this.issuer, this.inputClaimType, "myInputClaim");
            OutputPolicyClaim outputClaim = new OutputPolicyClaim(this.outputClaimType, "myOutputClaimValue");
            PolicyRule rule = new PolicyRule(AssertionsMatch.All, new[] { inputClaim }, outputClaim);
            store.RetrieveScopesReturnValue = new List<PolicyScope>() { new PolicyScope(new Uri("http://myScope"), new[] { rule }) };

            IEnumerable<Claim> evaluatedOutputClaims = evaluator.Evaluate(new Uri("http://myScope"), new[] { new Claim("http://myInputClaimType", "myInputClaim", string.Empty, "http://myInputClaimIssuer") });

            Assert.IsNotNull(evaluatedOutputClaims);
            Assert.AreEqual(1, evaluatedOutputClaims.Count());
            Assert.AreEqual("http://myOutputClaimType", evaluatedOutputClaims.ElementAt(0).Type);
            Assert.AreEqual("myOutputClaimValue", evaluatedOutputClaims.ElementAt(0).Value);
        }

        private class MockPolicyStore : IPolicyStore
        {
            public IEnumerable<PolicyScope> RetrieveScopesReturnValue { get; set; }

            public void AddPolicyRule(Uri scope, PolicyRule rule)
            {
                throw new NotImplementedException();
            }

            public IEnumerable<PolicyScope> RetrieveScopes()
            {
                return this.RetrieveScopesReturnValue;
            }

            public PolicyScope RetrieveScope(Uri scopeUri)
            {
                throw new NotImplementedException();
            }

            public void RemovePolicyRule(Uri scopeUri, PolicyRule rule)
            {
                throw new NotImplementedException();
            }

            public void AddIssuer(Uri scopeUri, Issuer issuer)
            {
                throw new NotImplementedException();
            }

            public void RemoveIssuer(Uri scopeUri, Issuer issuer)
            {
                throw new NotImplementedException();
            }

            public Issuer RetrieveIssuer(Uri scopeUri, string issuerName)
            {
                throw new NotImplementedException();
            }
        }
    }
}
