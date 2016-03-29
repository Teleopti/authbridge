using System.Linq;

namespace AuthBridge.Configuration
{
    using System;
    using System.Configuration;
    using Model;
    using Utilities;
    using System.Security.Cryptography.X509Certificates;
    using System.IO;

    public class DefaultConfigurationRepository : IConfigurationRepository
    {

		public static readonly DefaultConfigurationRepository Instance = new DefaultConfigurationRepository();

	    private DefaultConfigurationRepository()
	    {
			MultiProtocolIssuer = RetrieveMultiProtocolIssuer();
	    }

	    public ClaimProvider RetrieveIssuer(Uri identifier)
        {
            var configuration = ConfigurationManager.GetSection("authBridge/multiProtocolIssuer") as MultiProtocolIssuerSection;
            var claimProvider = configuration.ClaimProviders[identifier.ToString()];

            var issuer = claimProvider.ToModel();
            return issuer;
        }

	    public ClaimProvider[] RetrieveIssuers()
	    {
			var configuration = ConfigurationManager.GetSection("authBridge/multiProtocolIssuer") as MultiProtocolIssuerSection;
			var claimProviders = configuration.ClaimProviders.OfType<ClaimProviderElement>().Select(x=>x.ToModel());
		    return claimProviders.ToArray();
	    }

        private MultiProtocolIssuer RetrieveMultiProtocolIssuer()
        {
            var configuration = ConfigurationManager.GetSection("authBridge/multiProtocolIssuer") as MultiProtocolIssuerSection;

            if (string.IsNullOrEmpty(configuration.SigningCertificate.FindValue) && string.IsNullOrEmpty(configuration.SigningCertificateFile.PfxFilePath))
                throw new ConfigurationErrorsException("Specify either a signing certificate in the machine store or point to a PFX in the file system");

            X509Certificate2 cert = null;
            if (!string.IsNullOrEmpty(configuration.SigningCertificate.FindValue))
            {
                cert = CertificateUtil.GetCertificate(
                        configuration.SigningCertificate.StoreName,
                        configuration.SigningCertificate.StoreLocation,
                        configuration.SigningCertificate.FindValue);
            }
            else
            {
                var certRawData = File.ReadAllBytes(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, configuration.SigningCertificateFile.PfxFilePath));
                cert = new X509Certificate2(certRawData, configuration.SigningCertificateFile.Password, X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet);
            }
            
            return new MultiProtocolIssuer
            {
                Identifier = configuration.Identifier.ReplaceWithLocalhostWhenRelative(),
                ReplyUrl = configuration.ResponseEndpoint.ReplaceWithLocalhostWhenRelative(),
                SigningCertificate = cert
            };
        }

        public Scope RetrieveScope(Uri identifier)
        {
            var configuration = ConfigurationManager.GetSection("authBridge/multiProtocolIssuer") as MultiProtocolIssuerSection;

            var scope = configuration.Scopes[identifier.ToString()];
            var model = scope.ToModel();

            return model;
        }

		public ScopeElement RetrieveDefaultScope()
		{
			var configuration = ConfigurationManager.GetSection("authBridge/multiProtocolIssuer") as MultiProtocolIssuerSection;

			return configuration.Scopes.OfType<ScopeElement>().FirstOrDefault();
		}

	    public MultiProtocolIssuer MultiProtocolIssuer { get; private set; }
    }
}
