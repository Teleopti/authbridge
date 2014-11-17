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
		private static readonly ILog Logger = LogManager.GetLogger(typeof(OpenIdHandler));
		public RelativeOpenIdHandler(ClaimProvider issuer)
			: base(issuer)
		{
		}

		public override void ProcessSignInRequest(Scope scope, HttpContextBase httpContext)
		{
			var site = new Uri(httpContext.Request.Url.GetComponents(UriComponents.SchemeAndServer, UriFormat.Unescaped));
			var issuerUrl = Issuer.Url;
			var replyUrl = MultiProtocolIssuer.ReplyUrl;
			if (!issuerUrl.IsAbsoluteUri)
			{
				issuerUrl = new Uri(site,issuerUrl);
			}
			if (!replyUrl.IsAbsoluteUri)
			{
				replyUrl = new Uri(site,replyUrl);
			}

			Logger.Debug(string.Format("ProcessSignInRequest, Issuer.Url {0}, ReplyUrl {1}", issuerUrl, replyUrl));
			var client = new Clients.OpenIdClient(issuerUrl, MultiProtocolIssuer.Identifier);
			client.RequestAuthentication(httpContext, replyUrl);
		}

		public override IClaimsIdentity ProcessSignInResponse(string realm, string originalUrl, HttpContextBase httpContext)
		{
			var site = new Uri(httpContext.Request.Url.GetComponents(UriComponents.SchemeAndServer, UriFormat.Unescaped));
			var issuerUrl = Issuer.Url;
			var replyUrl = MultiProtocolIssuer.ReplyUrl;
			if (!issuerUrl.IsAbsoluteUri)
			{
				issuerUrl = new Uri(site, issuerUrl);
			}
			if (!replyUrl.IsAbsoluteUri)
			{
				replyUrl = new Uri(site, replyUrl);
			}
			var client = new Clients.OpenIdClient(issuerUrl, replyUrl);
			Logger.Debug(string.Format("ProcessSignInResponse"));
			Logger.Debug(string.Format("Issuer.Url {0}, originalUrl {1}", issuerUrl, originalUrl));

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