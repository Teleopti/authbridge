using System.Configuration;
using System.IdentityModel.Services.Configuration;
using System.Linq;

namespace AuthBridge.Web.Controllers
{
	public static class DefaultRedirectUrlProvider
	{
		public static string Get()
		{
			var identityModelServicesSection = ConfigurationManager.GetSection("system.identityModel.services") as SystemIdentityModelServicesSection;
			var service = identityModelServicesSection?.FederationConfigurationElements.OfType<FederationConfigurationElement>().FirstOrDefault();
			var wsFederation = service?.WsFederation;
			if (wsFederation != null)
			{
				return wsFederation.Issuer + "?wa=wsignin1.0&wtrealm=" + wsFederation.Realm + "&wctx=ru%3d" + wsFederation.SignOutReply;
			}
			return null;
		}
	}
}