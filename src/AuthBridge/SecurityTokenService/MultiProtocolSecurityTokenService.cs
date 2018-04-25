using System.Configuration;
using System.IdentityModel;
using System.IdentityModel.Configuration;
using System.IdentityModel.Protocols.WSTrust;
using System.Security.Claims;
using System.Web;
using AuthBridge.Clients.Util;
using AuthBridge.Utilities;
using log4net;

namespace AuthBridge.SecurityTokenService
{
    using System;
    using System.Collections.Generic;
    using System.ServiceModel;

    using ClaimsPolicyEngine;
    using Configuration;
    using System.Linq;

    public class MultiProtocolSecurityTokenService : System.IdentityModel.SecurityTokenService
    {
	    private static readonly ILog Logger = LogManager.GetLogger(typeof (MultiProtocolSecurityTokenService));
        private readonly IConfigurationRepository multiProtocolConfiguration;
        
        private Model.Scope scopeModel;

        public MultiProtocolSecurityTokenService(SecurityTokenServiceConfiguration configuration)
            : this(configuration, DefaultConfigurationRepository.Instance)
        {
        }

        public MultiProtocolSecurityTokenService(SecurityTokenServiceConfiguration configuration, IConfigurationRepository multiProtocolConfiguration)
            : base(configuration)
        {
            this.multiProtocolConfiguration = multiProtocolConfiguration;            
        }

        protected override Scope GetScope(ClaimsPrincipal principal, RequestSecurityToken request)
        {
			
            this.scopeModel = this.ValidateAppliesTo(new EndpointAddress(request.AppliesTo.Uri));

            var scope = new Scope(request.AppliesTo.Uri.OriginalString, SecurityTokenServiceConfiguration.SigningCredentials);
            scope.TokenEncryptionRequired = false;
			
            string replyTo;
            if (!string.IsNullOrEmpty(request.ReplyTo))
			{
				replyTo = request.ReplyTo;
			}
            else if (scopeModel.Url != null)
			{
				replyTo = scopeModel.Url.ToString();
	            if (ConfigurationManager.AppSettings.GetBoolSetting("UseRelativeConfiguration"))
	            {
		            replyTo =
			            new Uri(
				            new Uri(HttpContext.Current.Request.UrlConsideringLoadBalancerHeaders().GetComponents(UriComponents.SchemeAndServer, UriFormat.Unescaped)),
				            new Uri(scopeModel.Url.GetComponents(UriComponents.SchemeAndServer, UriFormat.Unescaped))
					            .MakeRelativeUri
					            (
						            scopeModel.Url)).ToString();
	            }
            }
            else
            {
                replyTo = scope.AppliesToAddress;
            }
            scope.ReplyToAddress = replyTo;

            return scope;
        }

        protected override ClaimsIdentity GetOutputClaimsIdentity(ClaimsPrincipal principal, RequestSecurityToken request, Scope scope)
        {
            if (null == principal)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            var outputIdentity = new ClaimsIdentity();
            IEnumerable<Claim> outputClaims;

	        var inputClaims = ((ClaimsIdentity)principal.Identity).Claims.ToArray();
	        if (scopeModel.UseClaimsPolicyEngine)
			{
				if (Logger.IsDebugEnabled)
				{
					Logger.DebugFormat("Mapping of claims. All values before are: {0}", String.Join(",", inputClaims.Select(i => i.ToString())));
				}
				IClaimsPolicyEvaluator evaluator = new ClaimsPolicyEvaluator(PolicyStoreFactory.Instance);
                outputClaims = evaluator.Evaluate(new Uri(scope.AppliesToAddress), inputClaims);
				if (Logger.IsDebugEnabled)
				{
					Logger.DebugFormat("Mapping of claims. All values after are: {0}", String.Join(",", outputClaims.Select(i => i.ToString())));
				}
			}
            else
            {
	            if (Logger.IsDebugEnabled)
	            {
		            Logger.DebugFormat("No mapping of claims. All values are: {0}", String.Join(",",inputClaims.Select(i => i.ToString())));
	            }
                outputClaims = inputClaims;
            }

            outputIdentity.AddClaims(outputClaims);
	        var nameIdentifierClaim = outputIdentity.Claims.SingleOrDefault(c => c.Type == ClaimTypes.NameIdentifier);
	        if (outputIdentity.Name == null && nameIdentifierClaim != null)
	        {
		        outputIdentity.AddClaim(new Claim(ClaimTypes.Name, nameIdentifierClaim.Value));
	        }

	        var isPersistentClaim = inputClaims.SingleOrDefault(c => c.Type == ClaimTypes.IsPersistent);
	        if (isPersistentClaim != null)
	        {
				outputIdentity.AddClaim(new Claim(ClaimTypes.IsPersistent, isPersistentClaim.Value));
	        }

			return outputIdentity;
        }

        private Model.Scope ValidateAppliesTo(EndpointAddress appliesTo)
        {
            if (appliesTo == null)
            {
                throw new ArgumentNullException(nameof(appliesTo));
            }

            var scope = this.multiProtocolConfiguration.RetrieveScope(HttpContext.Current.Request.UrlConsideringLoadBalancerHeaders() ,appliesTo.Uri);
            if (scope == null)
            {
                throw new InvalidRequestException($"The relying party '{appliesTo.Uri.OriginalString}' was not found.");
            }

            return scope;
        }
    }
}