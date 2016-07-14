using System.Configuration;
using System.IdentityModel;
using System.IdentityModel.Configuration;
using System.IdentityModel.Protocols.WSTrust;
using System.Security.Claims;
using System.Web;
using AuthBridge.Clients.Util;
using log4net;

namespace AuthBridge.SecurityTokenService
{
    using System;
    using System.Collections.Generic;
    using System.ServiceModel;

    using ClaimsPolicyEngine;
    using AuthBridge.Configuration;
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
	            if (ConfigurationManager.AppSettings.GetBoolSetting("UseRelativeConfiguration"))
	            {
		            var uri = new Uri(replyTo);
		            if (uri.IsAbsoluteUri)
		            {
			            replyTo = new Uri(uri.GetComponents(UriComponents.SchemeAndServer, UriFormat.Unescaped)).MakeRelativeUri(uri).ToString();
		            }
	            }
			}
            else if (scopeModel.Url != null)
			{
				replyTo = scopeModel.Url.ToString();
	            if (ConfigurationManager.AppSettings.GetBoolSetting("UseRelativeConfiguration"))
	            {
		            replyTo =
			            new Uri(
				            new Uri(HttpContext.Current.Request.Url.GetComponents(UriComponents.SchemeAndServer, UriFormat.Unescaped)),
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
                throw new ArgumentNullException("principal");
            }

            var outputIdentity = new ClaimsIdentity();
            IEnumerable<Claim> outputClaims;

            if (this.scopeModel.UseClaimsPolicyEngine)
            {
                IClaimsPolicyEvaluator evaluator = new ClaimsPolicyEvaluator(PolicyStoreFactory.Instance);
                outputClaims = evaluator.Evaluate(new Uri(scope.AppliesToAddress), ((ClaimsIdentity)principal.Identity).Claims);
            }
            else
            {
                outputClaims = ((ClaimsIdentity)principal.Identity).Claims;
            }

            outputIdentity.AddClaims(outputClaims);
            if (outputIdentity.Name == null && outputIdentity.Claims.SingleOrDefault(c => c.Type == ClaimTypes.NameIdentifier) != null)
                outputIdentity.AddClaim(new Claim(ClaimTypes.Name, outputIdentity.Claims.SingleOrDefault(c => c.Type == ClaimTypes.NameIdentifier).Value));

	        var isPersistent =
				((ClaimsIdentity)principal.Identity).Claims.SingleOrDefault(c => c.Type == ClaimTypes.IsPersistent);
	        if (isPersistent != null)
	        {
				outputIdentity.AddClaim(new Claim(ClaimTypes.IsPersistent, isPersistent.Value));
	        }

            return outputIdentity;
        }

        private Model.Scope ValidateAppliesTo(EndpointAddress appliesTo)
        {
            if (appliesTo == null)
            {
                throw new ArgumentNullException("appliesTo");
            }

            var scope = this.multiProtocolConfiguration.RetrieveScope(appliesTo.Uri);
            if (scope == null)
            {
                throw new InvalidRequestException(String.Format("The relying party '{0}' was not found.", appliesTo.Uri.OriginalString));
            }

            return scope;
        }
    }
}