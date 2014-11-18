using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Web;
using AuthBridge.Model;
using DotNetOpenAuth.AspNet;
using log4net;
using Microsoft.IdentityModel.Claims;

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
				Issuer.Url.MakeRelativeUri(new Uri(Issuer.Url.GetComponents(UriComponents.SchemeAndServer, UriFormat.Unescaped))));

			var replyUrl = new Uri(site,
				MultiProtocolIssuer.ReplyUrl.MakeRelativeUri(
					new Uri(MultiProtocolIssuer.ReplyUrl.GetComponents(UriComponents.SchemeAndServer, UriFormat.Unescaped))));

			var identifierUrl = new Uri(site,
				MultiProtocolIssuer.Identifier.MakeRelativeUri(
					new Uri(MultiProtocolIssuer.Identifier.GetComponents(UriComponents.SchemeAndServer, UriFormat.Unescaped))));

			Logger.Debug(string.Format("ProcessSignInRequest, Issuer.Url {0}, ReplyUrl {1}, Identifier {2}", issuerUrl, replyUrl, identifierUrl));
			var client = new Clients.OpenIdClient(issuerUrl, identifierUrl);
			client.RequestAuthentication(httpContext, replyUrl);
		}

		public override IClaimsIdentity ProcessSignInResponse(string realm, string originalUrl, HttpContextBase httpContext)
		{
			var site = new Uri(httpContext.Request.Url.GetComponents(UriComponents.SchemeAndServer, UriFormat.Unescaped));
			var issuerUrl = new Uri(site,
				Issuer.Url.MakeRelativeUri(new Uri(Issuer.Url.GetComponents(UriComponents.SchemeAndServer, UriFormat.Unescaped))));

			var identifierUrl = new Uri(site,
				MultiProtocolIssuer.Identifier.MakeRelativeUri(
					new Uri(MultiProtocolIssuer.Identifier.GetComponents(UriComponents.SchemeAndServer, UriFormat.Unescaped))));

			var client = new Clients.OpenIdClient(issuerUrl, identifierUrl);
			Logger.Debug(string.Format("ProcessSignInResponse"));
			Logger.Debug(string.Format("Issuer.Url {0}, originalUrl {1}, identifierUrl {2}", issuerUrl, originalUrl,
				identifierUrl));

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

			var identity = new ClaimsIdentity(claims, Issuer.Identifier.ToString());
			return identity;
		}
	}
}