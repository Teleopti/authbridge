using System.IdentityModel.Metadata;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using AuthBridge.Protocols.Saml;
using AuthBridge.Web.Services;
using Microsoft.Practices.Unity;

namespace AuthBridge.Web.Controllers
{
    using System;
    using System.IO;
    using System.Security.Cryptography.X509Certificates;
    using System.ServiceModel;
    using System.Web.Mvc;

    using Configuration;

    public class FederationMetadataController : Controller
    {
        private readonly IConfigurationRepository _configuration;

        public FederationMetadataController()
            : this(ServiceLocator.Container.Value.Resolve<IConfigurationRepository>())
        {
        }

        public FederationMetadataController(IConfigurationRepository configuration)
        {
            _configuration = configuration;
        }

        [AcceptVerbs(HttpVerbs.Get)]
        public ActionResult FederationMetadata(string organizationAlias)
        {
            var appRoot = HttpContext.GetRealAppRoot();
			var signInUrl = new Uri(appRoot, Url.RouteUrl("Process Request"));

            var serviceProperties = _configuration.MultiProtocolIssuer;

            return File(GetFederationMetadata(signInUrl, serviceProperties.Identifier, serviceProperties.SigningCertificate), "text/xml");
        }

        public byte[] GetFederationMetadata(Uri passiveSignInUrl, Uri identifier, X509Certificate2 signingCertificate)
        {
            var credentials = new X509SigningCredentials(signingCertificate);

            // Figure out the hostname exposed from Azure and what port the service is listening on
            var realm = new EndpointAddress(identifier);
            var passiveEndpoint = new EndpointReference(passiveSignInUrl.AbsoluteUri);

            // Create metadata document for relying party
            var entity = new EntityDescriptor(new EntityId(realm.Uri.AbsoluteUri));
            var securityTokenServiceDescriptor = CreateSecurityTokenServiceDescriptor(credentials, passiveEndpoint);
	        var applicationServiceDescriptor = CreateApplicationServiceDescriptor();
	        var serviceProviderSingleSignOnDescriptor = CreateServiceProviderSingleSignOnDescriptor(credentials);

	        entity.RoleDescriptors.Add(securityTokenServiceDescriptor);
	        entity.RoleDescriptors.Add(applicationServiceDescriptor);
	        entity.RoleDescriptors.Add(serviceProviderSingleSignOnDescriptor);
			// Set credentials with which to sign the metadata
			entity.SigningCredentials = credentials;

            // Serialize the metadata and convert it to an XElement
            var serializer = new MetadataSerializer();
            var stream = new MemoryStream();
            serializer.WriteMetadata(stream, entity);
            stream.Flush();

            return stream.ToArray();
        }

	    private ServiceProviderSingleSignOnDescriptor CreateServiceProviderSingleSignOnDescriptor(
            X509SigningCredentials credentials)
	    {
		    var indexedProtocolEndpointDictionary = new IndexedProtocolEndpointDictionary();
		    var indexedProtocolEndpoint = new IndexedProtocolEndpoint(0,
			    new Uri(Saml2Constants.PostBinding),
			    new Uri(_configuration.MultiProtocolIssuer.ReplyUrl.AbsoluteUri)) {IsDefault = true};
		    indexedProtocolEndpointDictionary.Add(0, indexedProtocolEndpoint);
		    var serviceProviderSingleSignOnDescriptor = new ServiceProviderSingleSignOnDescriptor(indexedProtocolEndpointDictionary);
			serviceProviderSingleSignOnDescriptor.ProtocolsSupported.Add(new Uri(Saml2Constants.Protocol));
		    serviceProviderSingleSignOnDescriptor.WantAssertionsSigned = true;
		    var identifier = new Uri("urn:Saml");
		    SamlHandler.Settings.TryGetValue(identifier, out var setting);
		    if (setting != null && setting.WantAuthnRequestsSigned)
		    {
			    serviceProviderSingleSignOnDescriptor.AuthenticationRequestsSigned = true;
			    var signingKey = new KeyDescriptor(credentials.SigningKeyIdentifier) { Use = KeyType.Signing };
			    serviceProviderSingleSignOnDescriptor.Keys.Add(signingKey);
		    }
		    else
		    {
			    serviceProviderSingleSignOnDescriptor.AuthenticationRequestsSigned = false;
		    }
		    
            return serviceProviderSingleSignOnDescriptor;
	    }

	    private ApplicationServiceDescriptor CreateApplicationServiceDescriptor()
	    {
		    var applicationServiceDescriptor = new ApplicationServiceDescriptor();
			applicationServiceDescriptor.ProtocolsSupported.Add(new Uri(WSFederationConstants.Namespace));
			applicationServiceDescriptor.PassiveRequestorEndpoints.Add(new EndpointReference(_configuration.MultiProtocolIssuer.ReplyUrl.AbsoluteUri));
		    return applicationServiceDescriptor;
	    }

	    private static SecurityTokenServiceDescriptor CreateSecurityTokenServiceDescriptor(X509SigningCredentials credentials,
		    EndpointReference passiveEndpoint)
	    {
		    var sts = new SecurityTokenServiceDescriptor();

		    // Add STS's signing key
		    var signingKey = new KeyDescriptor(credentials.SigningKeyIdentifier) {Use = KeyType.Signing};
		    sts.Keys.Add(signingKey);

		    // Add offered claim types
		    sts.ClaimTypesOffered.Add(new DisplayClaim(ClaimTypes.AuthenticationMethod));
		    sts.ClaimTypesOffered.Add(new DisplayClaim(ClaimTypes.AuthenticationInstant));
		    sts.ClaimTypesOffered.Add(new DisplayClaim(ClaimTypes.Name));

		    // Add passive federation endpoint
		    sts.PassiveRequestorEndpoints.Add(passiveEndpoint);

		    // Add supported protocols
		    sts.ProtocolsSupported.Add(new Uri(WSFederationConstants.Namespace));

		    // Add passive STS endpoint
		    sts.SecurityTokenServiceEndpoints.Add(passiveEndpoint);
		    return sts;
	    }
    }
}
