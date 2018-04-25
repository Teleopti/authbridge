using AuthBridge.Configuration;

namespace AuthBridge.Web.Services
{
	using Microsoft.Practices.Unity;
	using Model;
    using Protocols;

    public class DefaultProtocolDiscovery : IProtocolDiscovery
    {
	    public static IProtocolDiscovery Instance => new DefaultProtocolDiscovery();

	    public IProtocolHandler RetrieveProtocolHandler(ClaimProvider issuer)
        {
			return ServiceLocator.Container.Value.Resolve<IProtocolHandler>(
                              issuer.Protocol,
                              new ParameterOverride("issuer", issuer));
        }
    }
}
