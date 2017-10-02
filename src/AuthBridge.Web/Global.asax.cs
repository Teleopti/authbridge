using System.IdentityModel.Services;

namespace AuthBridge.Web
{
    using System.Web.Mvc;
    using System.Web.Routing;

    public class MvcApplication : System.Web.HttpApplication
    {
        public static void RegisterRoutes(RouteCollection routes)
        {
            routes.IgnoreRoute("{resource}.axd/{*pathInfo}");
            routes.MapRoute("Process Request", string.Empty, new { controller = "Authentication", action = "ProcessFederationRequest" });
            routes.MapRoute("Home Realm Discovery", "hrd", new { controller = "Authentication", action = "HomeRealmDiscovery" });
            routes.MapRoute("Process Authentication", "authenticate", new { controller = "Authentication", action = "Authenticate" });
            routes.MapRoute("Process Authentication Response", "response", new { controller = "Authentication", action = "ProcessResponse" });
			routes.MapRoute("Process ProcessIdpInitiatedRequest", "idp", new { controller = "Authentication", action = "ProcessIdpInitiatedRequest" });

            routes.MapRoute(
                "FederationMetadata",
                "FederationMetadata/2007-06/FederationMetadata.xml",
                new { controller = "FederationMetadata", action = "FederationMetadata" });
        }

        protected void Application_Start()
        {
            RegisterRoutes(RouteTable.Routes);
			
			FederatedAuthentication.FederationConfigurationCreated += (sender, e) =>
            {
                FederatedAuthentication.WSFederationAuthenticationModule.SecurityTokenReceived += WSFederationAuthenticationModule_SecurityTokenReceived;
				FederatedAuthentication.WSFederationAuthenticationModule.SignInError += WSFederationAuthenticationModule_SignInError;
			};
        }

		private void WSFederationAuthenticationModule_SignInError(object sender, ErrorEventArgs e)
		{
			// http://stackoverflow.com/questions/15904480/how-to-avoid-samlassertion-notonorafter-condition-is-not-satisfied-errors
			if (e.Exception.Message.StartsWith("ID4148") ||
				e.Exception.Message.StartsWith("ID4243") ||
				e.Exception.Message.StartsWith("ID4223"))
			{
				FederatedAuthentication.SessionAuthenticationModule.DeleteSessionTokenCookie();
				e.Cancel = true;
			}
		}

		void WSFederationAuthenticationModule_SecurityTokenReceived(object sender, SecurityTokenReceivedEventArgs e)
        {
            e.Cancel = true;
        }
    }
}