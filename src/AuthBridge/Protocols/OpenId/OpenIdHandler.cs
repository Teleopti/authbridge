using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Web;
using AuthBridge.Clients;
using AuthBridge.Model;
using DotNetOpenAuth.AspNet;
using log4net;
using Microsoft.IdentityModel.Claims;

namespace AuthBridge.Protocols.OpenID
{
	public class OpenIdHandler : ProtocolHandlerBase
	{
		private static readonly ILog Logger = LogManager.GetLogger(typeof (OpenIdHandler));
		public OpenIdHandler(ClaimProvider issuer)
			: base(issuer)
		{
		}

		public override void ProcessSignInRequest(Scope scope, HttpContextBase httpContext)
		{
			Logger.Debug(string.Format("ProcessSignInRequest, Issuer.Url {0}, ReplyUrl {1}", Issuer.Url, MultiProtocolIssuer.ReplyUrl));
			var client = new OpenIdClient(Issuer.Url,MultiProtocolIssuer.Identifier);
			client.RequestAuthentication(httpContext, MultiProtocolIssuer.ReplyUrl);
		}

		public override IClaimsIdentity ProcessSignInResponse(string realm, string originalUrl, HttpContextBase httpContext)
		{
            var client = new OpenIdClient(Issuer.Url, MultiProtocolIssuer.Identifier);
			Logger.Debug(string.Format("ProcessSignInResponse"));
			Logger.Debug(string.Format("Issuer.Url {0}, originalUrl {1}", Issuer.Url, originalUrl));

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