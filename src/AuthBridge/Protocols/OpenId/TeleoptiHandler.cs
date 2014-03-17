using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Web;
using AuthBridge.Clients;
using AuthBridge.Model;
using DotNetOpenAuth.AspNet;
using Microsoft.IdentityModel.Claims;

namespace AuthBridge.Protocols.OpenID
{
	public class TeleoptiHandler : ProtocolHandlerBase
	{
		public TeleoptiHandler(ClaimProvider issuer)
			: base(issuer)
		{
		}

		public override void ProcessSignInRequest(Scope scope, HttpContextBase httpContext)
		{
			var client = new TeleoptiClient();
			client.RequestAuthentication(httpContext, MultiProtocolIssuer.ReplyUrl);
		}

		public override IClaimsIdentity ProcessSignInResponse(string realm, string originalUrl, HttpContextBase httpContext)
		{
			var client = new TeleoptiClient();

			AuthenticationResult result;
			try
			{
				result = client.VerifyAuthentication(httpContext);
			}
			catch (WebException wex)
			{
				throw new InvalidOperationException(new StreamReader(wex.Response.GetResponseStream()).ReadToEnd(), wex);
			}

			var claims = new List<Claim>
				{
					new Claim(System.IdentityModel.Claims.ClaimTypes.NameIdentifier, result.ProviderUserId)
				};

			foreach (var claim in result.ExtraData)
			{
				claims.Add(new Claim("http://schemas.teleopti.com/" + claim.Key, claim.Value));
			}

			claims.Add(new Claim("http://schemas.teleopti.com/DataSource", "Teleopti CCC"));

			var identity = new ClaimsIdentity(claims, "Teleopti");

			identity.Claims.Add(new Claim("IdP/Claim1", "Hello from the Idp"));

			return identity;
		}
	}
}