using System.IdentityModel.Services;

namespace SampleRP
{
    using System.Web.Mvc;
    using System.Web.Routing;
    using System.Web;

	public class MvcApplication : HttpApplication
    {
        public static void RegisterRoutes(RouteCollection routes)
        {
            routes.IgnoreRoute("{resource}.axd/{*pathInfo}");

            routes.MapRoute("Logout", "logout", new { controller = "Home", action = "LogOut" });

            routes.MapRoute(
                "Fallback",
                "{controller}/{action}",
                new { controller = "Home", action = "UnSecure" });
        }

        protected void Application_Start()
        {
            RegisterRoutes(RouteTable.Routes);

			FederatedAuthentication.FederationConfigurationCreated += (sender, e) =>
			{
				FederatedAuthentication.WSFederationAuthenticationModule.SignedIn += WSFederationAuthenticationModule_SignedIn;
			};
			
        }

        void WSFederationAuthenticationModule_SignedIn(object sender, System.EventArgs e)
        {
            WSFederationMessage wsFederationMessage = WSFederationMessage.CreateFromFormPost(new HttpRequestWrapper(HttpContext.Current.Request));
            if (wsFederationMessage.Context != null)
            {
                var wctx = HttpUtility.ParseQueryString(wsFederationMessage.Context);
                string returnUrl = wctx["ru"];

                // TODO: check for absolute url and throw to avoid open redirects
                HttpContext.Current.Response.Redirect(returnUrl, false);
                HttpContext.Current.ApplicationInstance.CompleteRequest();
            }
        }
    }
}