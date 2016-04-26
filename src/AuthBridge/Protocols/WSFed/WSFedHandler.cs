using System;
using System.Web;
using AuthBridge.Model;
using log4net;
using System.IdentityModel.Selectors;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.Security.Claims;

namespace AuthBridge.Protocols.WSFed
{
    public class WSFedHandler : ProtocolHandlerBase
    {
        private readonly string _signingKeyThumbprint;
		private readonly string _wsfedEndpoint;

		private static readonly ILog Logger = LogManager.GetLogger(typeof(WSFedHandler));

	    public WSFedHandler(ClaimProvider issuer)
            : base(issuer)
        {
            _signingKeyThumbprint = issuer.Parameters["signingKeyThumbprint"];
			_wsfedEndpoint = issuer.Parameters["wsfedEndpoint"];
        }


        public override void ProcessSignInRequest(Scope scope, HttpContextBase httpContext)
        {
			Logger.Info(string.Format("process signin request! Identifier: {0}, ReplyUrl: {1}", MultiProtocolIssuer.Identifier, MultiProtocolIssuer.ReplyUrl));
	        var identityProviderUrl = string.IsNullOrEmpty(_wsfedEndpoint) ? Issuer.Url.ToString() : _wsfedEndpoint;
	        RequestAuthentication(httpContext, identityProviderUrl, MultiProtocolIssuer.Identifier.ToString(), MultiProtocolIssuer.ReplyUrl.ToString());
		}

        public override ClaimsIdentity ProcessSignInResponse(string realm, string originalUrl, HttpContextBase httpContext)
        {
			Logger.Info(string.Format("ProcessSignInResponse! realm: {0}, originalUrl: {1}", realm, originalUrl));

			var token = FederatedAuthentication.WSFederationAuthenticationModule.GetSecurityToken(httpContext.Request);

			FederatedAuthentication.FederationConfiguration.IdentityConfiguration.AudienceRestriction.AllowedAudienceUris.Add(MultiProtocolIssuer.Identifier);
			FederatedAuthentication.FederationConfiguration.IdentityConfiguration.SecurityTokenHandlers.Configuration.CertificateValidator = X509CertificateValidator.None;
			FederatedAuthentication.FederationConfiguration.IdentityConfiguration.SecurityTokenHandlers.Configuration.IssuerNameRegistry = new SimpleIssuerNameRegistry(this._signingKeyThumbprint);
            var identities = FederatedAuthentication.FederationConfiguration.IdentityConfiguration.SecurityTokenHandlers.ValidateToken(token);

            return identities[0];            
        }

        private static void RequestAuthentication(HttpContextBase httpContext, string identityProviderUrl, string realm, string replyUrl)
        {
            var signIn = new SignInRequestMessage(new Uri(identityProviderUrl), realm)
            {
                Context = replyUrl,
                Reply = replyUrl
            };

            var redirectUrl = signIn.WriteQueryString();
			Logger.Info(string.Format("RequestAuthentication! redirectUrl: {0}", redirectUrl));

            httpContext.Response.Redirect(redirectUrl, false);
			httpContext.ApplicationInstance.CompleteRequest();
        }

		private class SimpleIssuerNameRegistry : IssuerNameRegistry
        {
            private readonly string _trustedThumbprint;

            public SimpleIssuerNameRegistry(string trustedThumbprint)
            {
                _trustedThumbprint = trustedThumbprint;
            }

            public override string GetIssuerName(SecurityToken securityToken)
            {
				Logger.Info(string.Format("GetIssuerName!"));
                var x509 = securityToken as X509SecurityToken;
                if (x509 != null)
                {
	                Logger.Info(string.Format("Thumbprint! {0}", x509.Certificate.Thumbprint));
                    if (x509.Certificate.Thumbprint != null && x509.Certificate.Thumbprint.Equals(_trustedThumbprint, StringComparison.InvariantCultureIgnoreCase))
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