namespace AuthBridge.Web.Services
{
    using System;
    using System.Configuration;

    using Microsoft.Practices.Unity;
    using Microsoft.Practices.Unity.Configuration;

    using AuthBridge.Model;
    using AuthBridge.Protocols;

    public class DefaultProtocolDiscovery : IProtocolDiscovery
    {
        private readonly IUnityContainer container;

        public DefaultProtocolDiscovery()
        {
            var unitySection = ConfigurationManager.GetSection("unity") as UnityConfigurationSection;

            if (unitySection == null)
            {
                throw new ArgumentException(nameof(unitySection));
            }

            container = new UnityContainer();
            
            unitySection.Configure(container);
        }

        public IProtocolHandler RetrieveProtocolHandler(ClaimProvider issuer)
        {
			return container.Resolve<IProtocolHandler>(
                              issuer.Protocol,
                              new ParameterOverride("issuer", issuer));
        }
    }
}
