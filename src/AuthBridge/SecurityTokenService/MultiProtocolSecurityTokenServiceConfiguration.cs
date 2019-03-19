using System.IdentityModel.Configuration;
using System.IdentityModel.Tokens;
using Microsoft.Practices.Unity;
using System.Web;
using AuthBridge.Configuration;

namespace AuthBridge.SecurityTokenService
{
    

    public class MultiProtocolSecurityTokenServiceConfiguration : SecurityTokenServiceConfiguration
    {
        private const string MultiProtocolSecurityTokenServiceConfigurationKey = "MultiProtocolSecurityTokenServiceConfigurationKey";
        private static readonly object syncRoot = new object();
        private readonly Model.MultiProtocolIssuer serviceProperties;

        public MultiProtocolSecurityTokenServiceConfiguration(IConfigurationRepository configurationRepository) : base()
        {
            serviceProperties = configurationRepository.MultiProtocolIssuer;
        }

        public MultiProtocolSecurityTokenServiceConfiguration()
            : this(ServiceLocator.Container.Value.Resolve<IConfigurationRepository>())
        {
            SigningCredentials = new X509SigningCredentials(serviceProperties.SigningCertificate);
            TokenIssuerName = serviceProperties.Identifier.ToString();
            SecurityTokenService = typeof(MultiProtocolSecurityTokenService);
        }

        public static MultiProtocolSecurityTokenServiceConfiguration Current
        {
            get
            {
                var httpAppState = HttpContext.Current.Application;

                var customConfiguration = httpAppState.Get(MultiProtocolSecurityTokenServiceConfigurationKey) as MultiProtocolSecurityTokenServiceConfiguration;

                if (customConfiguration == null)
                {
                    lock (syncRoot)
                    {
                        customConfiguration = httpAppState.Get(MultiProtocolSecurityTokenServiceConfigurationKey) as MultiProtocolSecurityTokenServiceConfiguration;

                        if (customConfiguration == null)
                        {
                            customConfiguration = new MultiProtocolSecurityTokenServiceConfiguration();
                            httpAppState.Add(MultiProtocolSecurityTokenServiceConfigurationKey, customConfiguration);
                        }
                    }
                }

                return customConfiguration;
            }
        }
    }
}