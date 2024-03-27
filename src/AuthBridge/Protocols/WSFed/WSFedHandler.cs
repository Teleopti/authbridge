using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IdentityModel.Metadata;
using System.Web;
using AuthBridge.Model;
using log4net;
using System.IdentityModel.Selectors;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security;
using System.Xml;

namespace AuthBridge.Protocols.WSFed
{
	public class WsFedSetting
	{
		public string ReplyUrl { get; set; }
		public string[] SigningKeyThumbprints { get; set; }
		public string WsfedEndpoint { get; set; }
	}
    public class WSFedHandler : ProtocolHandlerBase
    {
	    private static readonly ConcurrentDictionary<Uri, WsFedSetting> Settings = new ConcurrentDictionary<Uri, WsFedSetting>(); 
		private static readonly ILog Logger = LogManager.GetLogger(typeof(WSFedHandler));
        
        private readonly Uri urn;

        public WSFedHandler(ClaimProvider issuer)
            : base(issuer)
		{
			urn = issuer.Identifier;
			if (Settings.ContainsKey(urn))
				return;
			var setting = new WsFedSetting
			{
				ReplyUrl = string.IsNullOrEmpty(issuer.Parameters["replyUrl"]) ? MultiProtocolIssuer.ReplyUrl.ToString() : issuer.Parameters["replyUrl"]
			};
			if (!string.IsNullOrEmpty(issuer.Parameters["metadataUrl"]))
			{
				ParseMetadata(issuer, setting);
			}
			else
			{
				setting.SigningKeyThumbprints = new [] { issuer.Parameters["signingKeyThumbprint"].ToLowerInvariant() };
				setting.WsfedEndpoint = issuer.Parameters["wsfedEndpoint"];
			}
			Settings.TryAdd(urn, setting);
        }

	    private void ParseMetadata(ClaimProvider issuer, WsFedSetting settings)
	    {
			ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12;
		    var serializer = new MetadataSerializer {CertificateValidationMode = X509CertificateValidationMode.None};
		    if ("true".Equals(issuer.Parameters["ignoreSslError"], StringComparison.InvariantCultureIgnoreCase))
		    {
			    ServicePointManager.ServerCertificateValidationCallback += (s, ce, ch, ssl) => true;
		    }
		    var metadata = serializer.ReadMetadata(XmlReader.Create(issuer.Parameters["metadataUrl"]));
		    var entityDescriptor = (EntityDescriptor) metadata;
		    var stsd = entityDescriptor.RoleDescriptors.OfType<SecurityTokenServiceDescriptor>().First();
		    if (stsd == null)
		    {
			    throw new InvalidOperationException("Missing SecurityTokenServiceDescriptor!");
		    }
		    Logger.Info($"Got SecurityTokenServiceDescriptor from metadata.");
		    settings.WsfedEndpoint = stsd.PassiveRequestorEndpoints.First().Uri.ToString();
		    Logger.Info($"First PassiveRequestorEndpoint in SecurityTokenServiceDescriptor from metadata: {settings.WsfedEndpoint}");
		    var x509DataClauses = stsd.Keys.Where(key => key.KeyInfo != null && key.Use == KeyType.Signing)
			    .Select(key => key.KeyInfo.OfType<X509RawDataKeyIdentifierClause>().First());
		    var tokens = new List<X509SecurityToken>();
		    tokens.AddRange(x509DataClauses.Select(token => new X509SecurityToken(new X509Certificate2(token.GetX509RawData()))));
		    Logger.Info($"Get signing keys: {tokens.Count}");
		    settings.SigningKeyThumbprints = tokens.Select(t => t.Certificate.Thumbprint.ToLowerInvariant()).ToArray();
			if (Logger.IsInfoEnabled)
				Logger.Info($"signing key thumbprints: {string.Join(", ",settings.SigningKeyThumbprints)}");
	    }


	    public override void ProcessSignInRequest(Scope scope, HttpContextBase httpContext)
        {
	        var result = Settings.TryGetValue(urn, out var setting);
	        if (!result)
	        {
		        throw new ArgumentException("No settings found for " + urn);
	        }
			Logger.Info($"process signin request! Identifier: {MultiProtocolIssuer.Identifier}, ReplyUrl: {setting.ReplyUrl}");
	        var identityProviderUrl = string.IsNullOrEmpty(setting.WsfedEndpoint) ? Issuer.Url.ToString() : setting.WsfedEndpoint;
	        RequestAuthentication(httpContext, identityProviderUrl, MultiProtocolIssuer.Identifier.ToString(), setting.ReplyUrl);
		}

        public override ClaimsIdentity ProcessSignInResponse(string realm, string originalUrl, HttpContextBase httpContext)
        {
			Logger.Info($"ProcessSignInResponse! realm: {realm}, originalUrl: {originalUrl}");

			var token = FederatedAuthentication.WSFederationAuthenticationModule.GetSecurityToken(httpContext.Request);

			FederatedAuthentication.FederationConfiguration.IdentityConfiguration.AudienceRestriction.AllowedAudienceUris.Add(MultiProtocolIssuer.Identifier);
			FederatedAuthentication.FederationConfiguration.IdentityConfiguration.SecurityTokenHandlers.Configuration.CertificateValidator = X509CertificateValidator.None;
			FederatedAuthentication.FederationConfiguration.IdentityConfiguration.SecurityTokenHandlers.Configuration.IssuerNameRegistry = new SimpleIssuerNameRegistry(Settings[urn].SigningKeyThumbprints);
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
			Logger.Info($"RequestAuthentication! redirectUrl: {redirectUrl}");

	        try
	        {
				httpContext.Response.Redirect(redirectUrl, false);
		        httpContext.ApplicationInstance.CompleteRequest();
			}
	        catch (Exception ex) when (HttpContext.Current.Response.HeadersWritten)
	        {
		        Logger.Error("exception while redirect to provider", ex);
	        }
        }

		private class SimpleIssuerNameRegistry : IssuerNameRegistry
        {
            private readonly string[] _trustedThumbprints;

            public SimpleIssuerNameRegistry(string[] trustedThumbprints)
            {
                _trustedThumbprints = trustedThumbprints;
            }

            public override string GetIssuerName(SecurityToken securityToken)
            {
				Logger.Info("GetIssuerName!");
                if (securityToken is X509SecurityToken x509)
                {
	                Logger.Info($"Thumbprint! {x509.Certificate.Thumbprint}");
                    if (x509.Certificate.Thumbprint != null && Array.IndexOf(_trustedThumbprints, x509.Certificate.Thumbprint.ToLowerInvariant()) > -1)
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