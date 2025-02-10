using System.Collections;
using System.Collections.Generic;
using System.Configuration;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Web;
using AuthBridge.Clients.Util;
using AuthBridge.Utilities;
using log4net;
using Microsoft.Practices.Unity;

namespace AuthBridge.Web.Controllers
{
    using System;
    using System.Globalization;
    using System.Security.Principal;
    using System.Web.Mvc;

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

        private const string AuthBridgeRedirect = "AuthBridgeRedirect";

        public AuthenticationController()
			: this(DefaultProtocolDiscovery.Instance, new FederationContext(), ServiceLocator.Container.Value.Resolve<IConfigurationRepository>())
        {
        }

        public AuthenticationController(IProtocolDiscovery protocolDiscovery, IFederationContext federationContext, IConfigurationRepository configuration)
        {
	        this.protocolDiscovery = protocolDiscovery;
			this.federationContext = federationContext;
            this.configuration = configuration;
            multiProtocolServiceProperties = this.configuration.MultiProtocolIssuer;
        }

		public ActionResult HomeRealmDiscovery(string errorMessage = "", string errorCode = "")
		{
			Logger.Info("HomeRealmDiscovery!");
			IEnumerable<ProviderViewModel> vms = new ProviderViewModel[]{};
			var showIdpOptions = (ConfigurationManager.AppSettings["ShowIdpOptions"] ?? "false").Trim().ToLower() == "true";
			if (showIdpOptions)
			{
				vms = configuration.RetrieveIssuers().Where(x => !x.IdpInitiatedOnly).Select(x => new ProviderViewModel
				{
					Identifier = x.Identifier.ToString(),
					DisplayName = x.DisplayName
				});
			}
			return View("Authenticate", new HrdViewModel {Providers = vms.ToArray(), ErrorCode = errorCode, ErrorMessage = errorMessage, ShowIdpOptions = showIdpOptions });
		}

		public ActionResult Authenticate()
        {
			Logger.Info("Authenticate!");
			var homeRealm = Request.QueryString[WSFederationConstants.Parameters.HomeRealm];
			// validation for Parameters.Context
			var context = Request.QueryString[WSFederationConstants.Parameters.Context];
			if (string.IsNullOrEmpty(homeRealm) || string.IsNullOrEmpty(homeRealm.Replace("urn:", "")))
			{
				return HomeRealmDiscovery();
			}
			if (!homeRealm.StartsWith("urn:"))
			{
				homeRealm = "urn:" + homeRealm;
			}
			var identifier = new Uri(homeRealm);
	        ClaimProvider issuer = configuration.RetrieveIssuer(identifier);
            if (issuer == null)
            {
                return HomeRealmDiscovery("", "TenantNotFound");
            }

            var handler = protocolDiscovery.RetrieveProtocolHandler(issuer);
            if (handler == null)
            {
                throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, "The protocol handler '{0}' was not found in the container", issuer.Protocol));
            }

			federationContext.IssuerName = issuer.Identifier.ToString();
	        var realm = federationContext.Realm;
	        if (string.IsNullOrEmpty(realm))
	        {
                realm = CreateFederationContextFromConfiguration();
            }
            var scope = configuration.RetrieveScope(new Uri(realm));
            if (scope == null)
            {
                throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, "The scope '{0}' was not found in the configuration", realm));
            }

            handler.ProcessSignInRequest(scope, HttpContext);

            return new EmptyResult();
		}

	    private void processResponse(Uri host, string issuerName, string originalUrl)
		{
			var issuer = configuration.RetrieveIssuer(new Uri(issuerName));
		    if (issuer == null)
				throw new InvalidOperationException("Error: no claim provider configured for " + issuerName);
			Logger.InfoFormat("ProcessResponse! issuer: {0}", issuer.DisplayName);

			var handler = protocolDiscovery.RetrieveProtocolHandler(issuer);
			Logger.InfoFormat("ProcessResponse! handler: {0}", handler);

			if (handler == null)
				throw new InvalidOperationException("Error: no handler for " + issuerName);

            ClaimsIdentity identity = handler.ProcessSignInResponse(
                                                                federationContext.Realm,
                                                                federationContext.OriginalUrl,
                                                                HttpContext);

	        var protocolIdentifier = multiProtocolServiceProperties.Identifier.ToString();
	        var issuerIdentifier = issuer.Identifier.ToString();
	        ClaimsIdentity outputIdentity = UpdateIssuer(identity, protocolIdentifier, issuerIdentifier);
            outputIdentity.AddClaim(new Claim(ClaimTypes.AuthenticationMethod, issuerIdentifier, ClaimValueTypes.String, protocolIdentifier));
            outputIdentity.AddClaim(new Claim(ClaimTypes.AuthenticationInstant, DateTime.UtcNow.ToString("o"), ClaimValueTypes.DateTime, protocolIdentifier));

			if (Logger.IsInfoEnabled)
			{
				foreach (var claim in outputIdentity.Claims)
				{
					Logger.InfoFormat("added claim, claim.Type: {0}, claim.Value: {1}, claim.ValueType: {2}, claim.Issuer: {3}",
						claim.Type, claim.Value, claim.ValueType, claim.Issuer);
				}
			}
			var sessionToken = new SessionSecurityToken(new ClaimsPrincipal(new[] { outputIdentity }), new TimeSpan(0, 30, 0));
			FederatedAuthentication.WSFederationAuthenticationModule.SetPrincipalAndWriteSessionToken(sessionToken, true);

            forceSameSiteNoneForSecureCookies();

            Logger.InfoFormat("Original url: {0}", originalUrl);
			Response.Redirect(originalUrl, false);
		}

        private void forceSameSiteNoneForSecureCookies()
        {
            var cookies = Response.Cookies;
            if (cookies == null) return;

            foreach (var cookieName in cookies.AllKeys)
            {
                var cookie = cookies[cookieName];
                if (cookie != null && cookie.Secure)
                {
                    cookie.SameSite = SameSiteMode.None;
                }
            }
        }

        [ValidateInput(false)]
		public void ProcessResponse()
		{
			Logger.Info("ProcessResponse!");
			if (string.IsNullOrEmpty(federationContext.IssuerName))
			{
				Logger.WarnFormat("The context cookie was not found. Try to sign in again.");
				throw new InvalidOperationException("");
			}
			if (Logger.IsInfoEnabled)
			{
				Logger.InfoFormat("ProcessResponse! federationContext.IssuerName: {0}", federationContext.IssuerName);
				Logger.InfoFormat("ProcessResponse! federationContext.OriginalUrl: {0}", federationContext.OriginalUrl);
			}

			Response.Cache.SetCacheability(HttpCacheability.NoCache);
			Response.Cache.SetExpires(DateTime.Today.AddYears(-10));
			Response.Cache.SetNoStore();

			processResponse(Request.UrlConsideringLoadBalancerHeaders(), federationContext.IssuerName, federationContext.OriginalUrl);

			federationContext.Destroy();
			HttpContext.ApplicationInstance.CompleteRequest();
		}

		public void ProcessIdpInitiatedRequest(string protocol)
		{
			var protocolIdentifier = "urn:" + protocol;

			var requestUrl = Request.UrlConsideringLoadBalancerHeaders();
			var scope = configuration.RetrieveDefaultScope();
			if (scope == null)
			{
				Response.Write(protocol + " IdP initiated failed.");
				Response.End();
				return;
			}
			var relayState = Request["RelayState"] ?? "";
			var relayHashState = Request["RelayHashState"];
			var returnUrl = string.IsNullOrWhiteSpace(relayState) ? "" : relayState;
            if (!returnUrl.Contains("WsFedOwinState"))
            {
                returnUrl = "ru=" + returnUrl;
            }

			if (!string.IsNullOrEmpty(relayHashState))
            {
                var httpCookie = new HttpCookie("returnHash",relayHashState){ Secure = Request.UrlConsideringLoadBalancerHeaders().IsTransportSecure()};
                if (!httpCookie.Secure)
                {
                    httpCookie.SameSite = SameSiteMode.Lax;
                }
                HttpContext.Response.Cookies.Add(httpCookie);
            }

			var originalUrl = $"?wa=wsignin1.0&wtrealm={Uri.EscapeDataString(scope.Identifier.OriginalString)}&wctx={returnUrl}&whr={Uri.EscapeDataString(protocolIdentifier)}";
			processResponse(requestUrl,protocolIdentifier, originalUrl);
			HttpContext.ApplicationInstance.CompleteRequest();
		}

	    public ActionResult ProcessFederationRequest()
        {
			Logger.Info("ProcessFederationRequest");
			var action = Request.QueryString[WSFederationConstants.Parameters.Action];

            var requestUri = Request.UrlConsideringLoadBalancerHeaders();
            switch (action)
            {
                case WSFederationConstants.Actions.SignIn:
                    {
                        var requestMessage = (SignInRequestMessage)WSFederationMessage.CreateFromUri(requestUri);
                        if (!string.IsNullOrEmpty(requestMessage.Reply))
                        {
                            var wreply = requestMessage.Reply.Trim();
                            if (!wreply.StartsWith(requestUri.GetLeftPart(UriPartial.Authority)))
                            {
                                var allowedWreply = ConfigurationManager.AppSettings["AllowWreply"];
                                if (string.IsNullOrEmpty(allowedWreply) || !wreply.StartsWith(allowedWreply))
                                {
                                    Logger.ErrorFormat("Got unsupported wreply {0}", wreply);
                                    throw new NotSupportedException("Invalid wreply");
                                }
                            }

                            var cookie = new HttpCookie(AuthBridgeRedirect, wreply);
                            if (Request.UrlConsideringLoadBalancerHeaders().IsTransportSecure())
                            {
                                cookie.SameSite = SameSiteMode.None;
                                cookie.Secure = true;
                            }

                            Response.AppendCookie(cookie);
                        }

                        if (User?.Identity != null && User.Identity.IsAuthenticated)
                        {
	                        try
	                        {
								var sts = new MultiProtocolSecurityTokenService(MultiProtocolSecurityTokenServiceConfiguration.Current);
								if (Logger.IsInfoEnabled)
								{
									var user = User.Identity as ClaimsIdentity;
									if (user?.Claims != null)
									{
										foreach (var claim in user.Claims)
										{
											Logger.InfoFormat(
												"claim, Issuer: {0}, OriginalIssuer: {1}, Type:{2}, Subject:{3}, Value: {4}, ValueType: {5}",
												claim.Issuer, claim.OriginalIssuer, claim.Type, claim.Subject, claim.Value,
												claim.ValueType);
										}
									}
									Logger.InfoFormat("Reply: {0}", requestMessage.Reply);
									Logger.InfoFormat("Before ProcessSignInRequest");
								}

                                if (!string.IsNullOrEmpty(Request.Cookies.Get(AuthBridgeRedirect)?.Value))
                                {
                                    var cookie = Request.Cookies.Get(AuthBridgeRedirect);
                                    requestMessage.Reply = cookie?.Value;
                                    cookie.Expires = DateTime.Now - TimeSpan.FromDays(1);
                                    Response.Cookies.Add(cookie);
                                }
								var responseMessage = FederatedPassiveSecurityTokenServiceOperations.ProcessSignInRequest(requestMessage, new ClaimsPrincipal(User), sts);
								responseMessage.Write(Response.Output);
							}
	                        finally
	                        {
								FederatedAuthentication.SessionAuthenticationModule.DeleteSessionTokenCookie();
							}
                            Response.Flush();
                            HttpContext.ApplicationInstance.CompleteRequest();
                        }
                        else
                        {
                            // user not authenticated yet, look for whr, if not there go to HomeRealmDiscovery page
							Logger.InfoFormat("User is not authenticated yet, redirecting to given realm.");
                            CreateFederationContext();

                            if (string.IsNullOrEmpty(Request.QueryString[WSFederationConstants.Parameters.HomeRealm]))
                            {
                                return HomeRealmDiscovery(HttpUtility.HtmlEncode(HttpUtility.ParseQueryString(requestMessage.Context).Get("em")));
                            }
	                        return Authenticate();
                        }
                    }

                    break;
                case WSFederationConstants.Actions.SignOut:
                    {
                        var requestMessage = (SignOutRequestMessage)WSFederationMessage.CreateFromUri(requestUri);
						var replyTo = requestMessage.Reply;
						if (!string.IsNullOrEmpty(replyTo) && ConfigurationManager.AppSettings.GetBoolSetting("UseRelativeConfiguration"))
						{
							var uri = new Uri(replyTo);
							if (uri.IsAbsoluteUri)
							{
								replyTo = "/" + new Uri(uri.GetComponents(UriComponents.SchemeAndServer, UriFormat.Unescaped)).MakeRelativeUri(uri);
							}
						}
                        FederatedPassiveSecurityTokenServiceOperations.ProcessSignOutRequest(requestMessage, new ClaimsPrincipal(User), replyTo, HttpContext.ApplicationInstance.Response);
                        HttpContext.ApplicationInstance.CompleteRequest();
					}

                    break;
                default:
                    Response.AddHeader("X-XRDS-Location",new Uri(requestUri,Response.ApplyAppPathModifier("~/xrds.aspx")).AbsoluteUri);
                    return new EmptyResult();
            }

            return null;
        }

        protected override void OnActionExecuting(ActionExecutingContext filterContext)
        {
            if (filterContext.HttpContext.User.Identity is WindowsIdentity)
                throw new InvalidOperationException("Windows authentication is not supported.");
        }

        private static ClaimsIdentity UpdateIssuer(ClaimsIdentity input, string issuer, string originalIssuer)
        {
            ClaimsIdentity outputIdentity = new ClaimsIdentity(new Claim[] {}, input.AuthenticationType);
            foreach (var claim in input.Claims)
            {
	            Logger.InfoFormat("outputIdentity.Claims.Add {0},{1},{2},{3}, {4}", claim.Type, claim.Value, claim.ValueType, issuer, originalIssuer);
                outputIdentity.AddClaim(new Claim(claim.Type, claim.Value, claim.ValueType, issuer, originalIssuer));
            }

            return outputIdentity;
        }

        private void CreateFederationContext()
        {
            federationContext.OriginalUrl = HttpContext.Request.UrlConsideringLoadBalancerHeaders().PathAndQuery;
            federationContext.Realm = Request.QueryString[WSFederationConstants.Parameters.Realm];
            federationContext.IssuerName = Request.QueryString[WSFederationConstants.Parameters.HomeRealm];
            federationContext.Context = Request.QueryString[WSFederationConstants.Parameters.Context];
        }

        private string CreateFederationContextFromConfiguration()
        {
            var realm = FederatedAuthentication.FederationConfiguration.WsFederationConfiguration.Realm;
            var returnUrl = FederatedAuthentication.FederationConfiguration.WsFederationConfiguration.SignOutReply;
            federationContext.OriginalUrl = FederatedAuthentication.FederationConfiguration.WsFederationConfiguration.Issuer + "?wa=wsignin1.0&wtrealm=" + HttpUtility.UrlEncode(realm)+ "&wctx=ru%3d" + HttpUtility.UrlEncode(returnUrl);
            federationContext.Realm = realm;
            federationContext.Context = "ru%3d" + returnUrl;
	        return realm;
        }
    }

	public class HrdViewModel
	{
		public ProviderViewModel[] Providers { get; set; }
		public string ErrorMessage { get; set; }
		public string ErrorCode { get; set; }
		public bool ShowIdpOptions { get; set; }
	}
}
