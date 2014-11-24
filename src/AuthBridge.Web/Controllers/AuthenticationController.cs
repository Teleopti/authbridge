using System.Linq;
using log4net;

namespace AuthBridge.Web.Controllers
{
    using System;
    using System.Globalization;
    using System.Security.Principal;
    using System.Web.Mvc;

    using Microsoft.IdentityModel.Claims;
    using Microsoft.IdentityModel.Protocols.WSFederation;
    using Microsoft.IdentityModel.Tokens;
    using Microsoft.IdentityModel.Web;

    using Services;

    using Configuration;
    using Model;
    using SecurityTokenService;

    [HandleError]
    public class AuthenticationController : Controller
    {
	    private static readonly ILog Logger = LogManager.GetLogger(typeof (AuthenticationController));
        private readonly IProtocolDiscovery protocolDiscovery;

        private readonly IFederationContext federationContext;

        private readonly IConfigurationRepository configuration;

        private readonly MultiProtocolIssuer multiProtocolServiceProperties;

        public AuthenticationController()
            : this(new DefaultProtocolDiscovery(), new FederationContext(), new DefaultConfigurationRepository())
        {
        }

        public AuthenticationController(IProtocolDiscovery defaultProtocolDiscovery, IFederationContext federationContext, IConfigurationRepository configuration)
        {
            protocolDiscovery = defaultProtocolDiscovery;
            this.federationContext = federationContext;
            this.configuration = configuration;
            multiProtocolServiceProperties = this.configuration.RetrieveMultiProtocolIssuer();
        }

        public ActionResult HomeRealmDiscovery()
        {
	        var vms=configuration.RetrieveIssuers().Select(x => new ProviderViewModel
	        {
		        Identifier = x.Identifier.ToString(),
		        DisplayName = x.DisplayName
	        });
            return View("Authenticate", vms.ToArray());
        }
        
        public ActionResult Authenticate()
        {            
            var identifier = new Uri(Request.QueryString[WSFederationConstants.Parameters.HomeRealm]);

            ClaimProvider issuer = configuration.RetrieveIssuer(identifier);
            if (issuer == null)
            {
                return HomeRealmDiscovery();
            }

            var handler = protocolDiscovery.RetrieveProtocolHandler(issuer);
            if (handler == null)
            {
                throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, "The protocol handler '{0}' was not found in the container", issuer.Protocol));
            }

			federationContext.IssuerName = issuer.Identifier.ToString();
	        if (string.IsNullOrEmpty(federationContext.Realm))
	        {
				throw new InvalidOperationException("The context cookie was not found. Try to sign in again.");
	        }
            var scope = configuration.RetrieveScope(new Uri(federationContext.Realm));
            if (scope == null)
            {
                throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, "The scope '{0}' was not found in the configuration", federationContext.Realm));
            }

            handler.ProcessSignInRequest(scope, HttpContext);
            
            return new EmptyResult();
        }

        [ValidateInput(false)]
        public void ProcessResponse()
        {
            if (string.IsNullOrEmpty(federationContext.IssuerName))
            {
				throw new InvalidOperationException("The context cookie was not found. Try to sign in again.");
            }

            var issuer = configuration.RetrieveIssuer(new Uri(federationContext.IssuerName));

            var handler = protocolDiscovery.RetrieveProtocolHandler(issuer);

            if (handler == null)
                throw new InvalidOperationException();

            IClaimsIdentity identity = handler.ProcessSignInResponse(
                                                                federationContext.Realm,
                                                                federationContext.OriginalUrl,
                                                                HttpContext);

	        var protocolIdentifier = multiProtocolServiceProperties.Identifier.ToString();
	        var issuerIdentifier = issuer.Identifier.ToString();
	        IClaimsIdentity outputIdentity = UpdateIssuer(identity, protocolIdentifier, issuerIdentifier);
            outputIdentity.Claims.Add(new Claim(ClaimTypes.AuthenticationMethod, issuerIdentifier, ClaimValueTypes.String, protocolIdentifier));
            outputIdentity.Claims.Add(new Claim(ClaimTypes.AuthenticationInstant, DateTime.Now.ToString("o"), ClaimValueTypes.Datetime, protocolIdentifier));

            var sessionToken = new SessionSecurityToken(new ClaimsPrincipal(new[] { outputIdentity }));
            FederatedAuthentication.SessionAuthenticationModule.CookieHandler.RequireSsl = !HttpContext.IsDebuggingEnabled;
            FederatedAuthentication.WSFederationAuthenticationModule.SetPrincipalAndWriteSessionToken(sessionToken, true);

            // TODO: sign context cookie to avoid tampering with this value
			Logger.InfoFormat("Original url: {0}", federationContext.OriginalUrl);
            Response.Redirect(federationContext.OriginalUrl, false);
            federationContext.Destroy();
            HttpContext.ApplicationInstance.CompleteRequest();
        }

        public ActionResult ProcessFederationRequest()
        {
            var action = Request.QueryString[WSFederationConstants.Parameters.Action];

            try
            {
                switch (action)
                {
                    case WSFederationConstants.Actions.SignIn:
                        {
                            var requestMessage = (SignInRequestMessage)WSFederationMessage.CreateFromUri(Request.Url);
                            
                            if (User != null && User.Identity != null && User.Identity.IsAuthenticated)
                            {
                                var sts = new MultiProtocolSecurityTokenService(MultiProtocolSecurityTokenServiceConfiguration.Current);
                                var responseMessage = FederatedPassiveSecurityTokenServiceOperations.ProcessSignInRequest(requestMessage, User, sts);
                                responseMessage.Write(Response.Output);
                                Response.Flush();
                                Response.End();
                                HttpContext.ApplicationInstance.CompleteRequest();
                            }
                            else
                            {
                                // user not authenticated yet, look for whr, if not there go to HomeRealmDiscovery page
                                CreateFederationContext();

                                if (string.IsNullOrEmpty(Request.QueryString[WSFederationConstants.Parameters.HomeRealm]))
                                {
                                    return RedirectToAction("HomeRealmDiscovery");
                                }
	                            return Authenticate();
                            }
                        }

                        break;
                    case WSFederationConstants.Actions.SignOut:
                        {
                            var requestMessage = (SignOutRequestMessage)WSFederationMessage.CreateFromUri(Request.Url);
                            FederatedPassiveSecurityTokenServiceOperations.ProcessSignOutRequest(requestMessage, User, requestMessage.Reply, HttpContext.ApplicationInstance.Response);
                        }

                        break;
                    default:
                        Response.AddHeader("X-XRDS-Location",new Uri(Request.Url,Response.ApplyAppPathModifier("~/xrds.aspx")).AbsoluteUri);
                        return new EmptyResult();
                }
            }
            catch (Exception exception)
            {
                throw new Exception("An unexpected error occurred when processing the request. See inner exception for details.", exception);
            }

            return null;
        }

        protected override void OnActionExecuting(ActionExecutingContext filterContext)
        {
            if (filterContext.HttpContext.User.Identity is WindowsIdentity)
                throw new InvalidOperationException("Windows authentication is not supported.");
        }

        private static IClaimsIdentity UpdateIssuer(IClaimsIdentity input, string issuer, string originalIssuer)
        {
            IClaimsIdentity outputIdentity = new ClaimsIdentity();
            foreach (var claim in input.Claims)
            {
                outputIdentity.Claims.Add(new Claim(claim.ClaimType, claim.Value, claim.ValueType, issuer, originalIssuer));
            }

            return outputIdentity;
        }

        private void CreateFederationContext()
        {
            federationContext.OriginalUrl = HttpContext.Request.Url.PathAndQuery;
            federationContext.Realm = Request.QueryString[WSFederationConstants.Parameters.Realm];
            federationContext.IssuerName = Request.QueryString[WSFederationConstants.Parameters.HomeRealm];
        }
    }
}
