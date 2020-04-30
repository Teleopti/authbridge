using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Web;
using AuthBridge.Clients;
using AuthBridge.Model;
using DotNetOpenAuth.AspNet;
using log4net;

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
			Logger.Debug($"ProcessSignInRequest, Issuer.Url {Issuer.Url}, ReplyUrl {MultiProtocolIssuer.ReplyUrl}");
			var client = new OpenIdClient(Issuer.Url,MultiProtocolIssuer.Identifier);
			client.RequestAuthentication(httpContext, MultiProtocolIssuer.ReplyUrl);
		}

		public override ClaimsIdentity ProcessSignInResponse(string realm, string originalUrl, HttpContextBase httpContext)
		{
            var client = new OpenIdClient(Issuer.Url, MultiProtocolIssuer.Identifier);
			Logger.Debug("ProcessSignInResponse");
			Logger.Debug($"Issuer.Url {Issuer.Url}, originalUrl {originalUrl}");

			AuthenticationResult result;
			try
			{
                var op_endpoint = httpContext.Request["openid.op_endpoint"];
                if (!string.IsNullOrEmpty(op_endpoint))
                {
                    if (!op_endpoint.StartsWith(Issuer.Url.AbsoluteUri, StringComparison.InvariantCultureIgnoreCase))
                    {
                        Logger.ErrorFormat("Issuer.Url {0}, openid.op_endpoint {1}", Issuer.Url, op_endpoint);
						throw new InvalidOperationException("openid.op_endpoint needs to match the issuer url");
                    }
                }

				result = client.VerifyAuthentication(httpContext);
				Logger.Debug($"ProviderUserId {result.ProviderUserId}");
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

			var identity = new ClaimsIdentity(claims, Issuer.Identifier.ToString());
			return identity;
		}
	}
}