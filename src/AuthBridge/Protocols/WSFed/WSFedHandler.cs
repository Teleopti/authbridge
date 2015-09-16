using System;
using System.Web;
using AuthBridge.Model;
using log4net;
using Microsoft.IdentityModel.Claims;
using Microsoft.IdentityModel.Protocols.WSFederation;
using Microsoft.IdentityModel.Web;
using System.IdentityModel.Selectors;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens;

namespace AuthBridge.Protocols.WSFed
{
    public class WSFedHandler : ProtocolHandlerBase
    {
        private readonly string _signingKeyThumbprint;

		private static readonly ILog Logger = LogManager.GetLogger(typeof(WSFedHandler));

	    public WSFedHandler(ClaimProvider issuer)
            : base(issuer)
        {
            _signingKeyThumbprint = issuer.Parameters["signingKeyThumbprint"];
        }


        public override void ProcessSignInRequest(Scope scope, HttpContextBase httpContext)
        {
			RequestAuthentication(httpContext, Issuer.Url.ToString(), MultiProtocolIssuer.Identifier.ToString(), MultiProtocolIssuer.ReplyUrl.ToString());    
        }

        public override IClaimsIdentity ProcessSignInResponse(string realm, string originalUrl, HttpContextBase httpContext)
        {
            var token = FederatedAuthentication.WSFederationAuthenticationModule.GetSecurityToken(HttpContext.Current.Request);
            FederatedAuthentication.ServiceConfiguration.AudienceRestriction.AllowedAudienceUris.Add(MultiProtocolIssuer.Identifier);
            FederatedAuthentication.ServiceConfiguration.SecurityTokenHandlers.Configuration.CertificateValidator = X509CertificateValidator.None;
            FederatedAuthentication.ServiceConfiguration.SecurityTokenHandlers.Configuration.IssuerNameRegistry = new SimpleIssuerNameRegistry(this._signingKeyThumbprint);

            ClaimsIdentityCollection identities = FederatedAuthentication.ServiceConfiguration.SecurityTokenHandlers.ValidateToken(token);

            return identities[0];            
        }

        private void RequestAuthentication(HttpContextBase httpContext, string identityProviderUrl, string realm, string replyUrl)
        {
            var signIn = new SignInRequestMessage(new Uri(identityProviderUrl), realm)
            {
                Context = replyUrl,
                Reply = replyUrl
            };

            var redirectUrl = signIn.WriteQueryString();

            httpContext.Response.Redirect(redirectUrl, false);
            httpContext.ApplicationInstance.CompleteRequest();
        }

        private class SimpleIssuerNameRegistry : IssuerNameRegistry
        {
            private readonly string _trustedThumbrpint;

            public SimpleIssuerNameRegistry(string trustedThumbprint)
            {
                _trustedThumbrpint = trustedThumbprint;
            }

            public override string GetIssuerName(SecurityToken securityToken)
            {
                var x509 = securityToken as X509SecurityToken;
                if (x509 != null)
                {
                    if (x509.Certificate.Thumbprint != null && x509.Certificate.Thumbprint.Equals(_trustedThumbrpint, StringComparison.InvariantCultureIgnoreCase))
                    {
                        return x509.Certificate.Subject;
                    }
                }
				Logger.Error("Cannot verify thumbprint in IssuerNameRegistry.");
                return null;
            }
        }
    }
}