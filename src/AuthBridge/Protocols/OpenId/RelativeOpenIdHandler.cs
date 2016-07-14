using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Web;
using AuthBridge.Model;
using DotNetOpenAuth.AspNet;
using log4net;

namespace AuthBridge.Protocols.OpenID
{
	public class RelativeOpenIdHandler : ProtocolHandlerBase
	{
		private static readonly ILog Logger = LogManager.GetLogger(typeof(RelativeOpenIdHandler));
		public RelativeOpenIdHandler(ClaimProvider issuer)
			: base(issuer)
		{
		}

		public override void ProcessSignInRequest(Scope scope, HttpContextBase httpContext)
		{
			var site = new Uri(httpContext.Request.Url.GetComponents(UriComponents.SchemeAndServer, UriFormat.Unescaped));
			var issuerUrl = new Uri(site,
				new Uri(Issuer.Url.GetComponents(UriComponents.SchemeAndServer, UriFormat.Unescaped)).MakeRelativeUri(Issuer.Url));

			var replyUrl = new Uri(site,
				new Uri(MultiProtocolIssuer.ReplyUrl.GetComponents(UriComponents.SchemeAndServer, UriFormat.Unescaped)).MakeRelativeUri(MultiProtocolIssuer.ReplyUrl));

			var identifierUrl = new Uri(site,
				new Uri(MultiProtocolIssuer.Identifier.GetComponents(UriComponents.SchemeAndServer, UriFormat.Unescaped)).MakeRelativeUri(MultiProtocolIssuer.Identifier));

			Logger.Debug(string.Format("ProcessSignInRequest, Issuer.Url {0}, ReplyUrl {1}, Identifier {2}", issuerUrl, replyUrl, identifierUrl));
			var client = new Clients.RelativeOpenIdClient(issuerUrl, identifierUrl);


			Logger.InfoFormat("Status code: {0}", httpContext.Response.StatusCode);

			scope.Url = new Uri(site,
				new Uri(scope.Url.GetComponents(UriComponents.SchemeAndServer, UriFormat.Unescaped)).MakeRelativeUri(scope.Url));
			client.RequestAuthentication(httpContext, replyUrl);
}

		public override ClaimsIdentity ProcessSignInResponse(string realm, string originalUrl, HttpContextBase httpContext)
		{
			var site = new Uri(httpContext.Request.Url.GetComponents(UriComponents.SchemeAndServer, UriFormat.Unescaped));
			var issuerUrl = new Uri(site,
				new Uri(Issuer.Url.GetComponents(UriComponents.SchemeAndServer, UriFormat.Unescaped)).MakeRelativeUri(Issuer.Url));

			var identifierUrl = new Uri(site,
				new Uri(MultiProtocolIssuer.Identifier.GetComponents(UriComponents.SchemeAndServer, UriFormat.Unescaped)).MakeRelativeUri(MultiProtocolIssuer.Identifier));

			var client = new Clients.RelativeOpenIdClient(issuerUrl, identifierUrl);
			Logger.Debug("ProcessSignInResponse");
			Logger.DebugFormat("Issuer.Url {0}, originalUrl {1}, identifierUrl {2}", issuerUrl, originalUrl,
				identifierUrl);

			AuthenticationResult result;
			try
			{
				result = client.VerifyAuthentication(httpContext);
				Logger.Debug(string.Format("ProviderUserId {0}", result.ProviderUserId));
			}
			catch (WebException wex)
			{
				throw new InvalidOperationException(new StreamReader(wex.Response.GetResponseStream()).ReadToEnd(), wex);
			}

			var claims = new List<Claim>
			{
				new Claim(System.IdentityModel.Claims.ClaimTypes.NameIdentifier, result.ProviderUserId)
			};
			claims.AddRange(result.ExtraData.Select(claim => new Claim(claim.Key, claim.Value)));

			var identity = new ClaimsIdentity(claims, issuerUrl.ToString());
			return identity;
		}
	}
}