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
        private static IUnityContainer _container;

	    private DefaultProtocolDiscovery()
	    {
	    }

	    public static IProtocolDiscovery Instance
	    {
		    get
		    {
			    if (_container == null)
			    {
					var unitySection = ConfigurationManager.GetSection("unity") as UnityConfigurationSection;
					if (unitySection == null)
					{
						throw new ArgumentException(nameof(unitySection));
					}
					_container = new UnityContainer();
					unitySection.Configure(_container);
				}
			    return new DefaultProtocolDiscovery();
			}
		}

	    public IProtocolHandler RetrieveProtocolHandler(ClaimProvider issuer)
        {
			return _container.Resolve<IProtocolHandler>(
                              issuer.Protocol,
                              new ParameterOverride("issuer", issuer));
        }
    }
}
