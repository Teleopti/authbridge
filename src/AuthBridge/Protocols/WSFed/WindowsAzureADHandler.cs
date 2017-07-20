using System.IdentityModel.Services;
using System.Security.Claims;

namespace AuthBridge.Protocols.WSFed
{
    using System;
    using System.Web;
    using Model;
    using System.IdentityModel.Selectors;
    using System.IdentityModel.Tokens;

    public class WindowsAzureADHandler : ProtocolHandlerBase
    {
        private readonly string signingKeyThumbprint;
        private readonly string tenantId;
        private readonly string appPrincipalId;
        private readonly string realmFormat;

        public WindowsAzureADHandler(ClaimProvider issuer)
            : base(issuer)
        {
            signingKeyThumbprint = issuer.Parameters["signingKeyThumbprint"];
            tenantId = issuer.Parameters["tenantId"];
            appPrincipalId = issuer.Parameters["appPrincipalId"];
            realmFormat = issuer.Parameters["realmFormat"];
        }


        public override void ProcessSignInRequest(Scope scope, HttpContextBase httpContext)
        {
            string localAuthorityRealm = realmFormat
                                .Replace("{tenantId}", tenantId)
                                .Replace("{appPrincipalId}", appPrincipalId);

            RequestAuthentication(httpContext, this.Issuer.Url.ToString(), localAuthorityRealm, this.MultiProtocolIssuer.ReplyUrl.ToString());    
        }

        public override ClaimsIdentity ProcessSignInResponse(string realm, string originalUrl, HttpContextBase httpContext)
        {
            string localAuthorityRealm = realmFormat
                                .Replace("{tenantId}", tenantId)
                                .Replace("{appPrincipalId}", appPrincipalId);

            var token = FederatedAuthentication.WSFederationAuthenticationModule.GetSecurityToken(httpContext.Request);
            FederatedAuthentication.FederationConfiguration.IdentityConfiguration.AudienceRestriction.AllowedAudienceUris.Add(new Uri(localAuthorityRealm));
            FederatedAuthentication.FederationConfiguration.IdentityConfiguration.SecurityTokenHandlers.Configuration.CertificateValidator = X509CertificateValidator.None;
            FederatedAuthentication.FederationConfiguration.IdentityConfiguration.SecurityTokenHandlers.Configuration.IssuerNameRegistry = new SimpleIssuerNameRegistry(this.signingKeyThumbprint);

            var identities = FederatedAuthentication.FederationConfiguration.IdentityConfiguration.SecurityTokenHandlers.ValidateToken(token);

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
            private readonly string trustedThumbrpint;

            public SimpleIssuerNameRegistry(string trustedThumbprint)
            {
                trustedThumbrpint = trustedThumbprint;
            }

            public override string GetIssuerName(SecurityToken securityToken)
            {
                var x509 = securityToken as X509SecurityToken;
                if (x509 != null)
                {
                    if (x509.Certificate.Thumbprint.Equals(trustedThumbrpint, StringComparison.OrdinalIgnoreCase))
                    {
                        return x509.Certificate.Subject;
                    }
                }

                return null;
            }
        }
 
    }
}