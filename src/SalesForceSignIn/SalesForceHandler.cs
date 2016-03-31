using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Web;
using AuthBridge.Clients;
using AuthBridge.Model;
using AuthBridge.Protocols;
using DotNetOpenAuth.AspNet;
using Microsoft.IdentityModel.Claims;

namespace SalesForceSignIn
{
	public class SalesForceHandler : ProtocolHandlerBase
	{
		private readonly ClaimProvider issuer;
		private readonly string appId;
		private readonly string secretKey;

		public SalesForceHandler(ClaimProvider issuer) : base(issuer)
		{
			if (issuer == null)
				throw new ArgumentNullException("issuer");

			this.issuer = issuer;
			this.appId = this.issuer.Parameters["wll_appid"];
			this.secretKey = this.issuer.Parameters["wll_secret"];
		}

		public override void ProcessSignInRequest(Scope scope, HttpContextBase httpContext)
		{
			var client = new SalesforceClient(appId, secretKey);
			client.RequestAuthentication(httpContext, MultiProtocolIssuer.ReplyUrl);
		}

		public override IClaimsIdentity ProcessSignInResponse(string realm, string originalUrl, HttpContextBase httpContext)
		{
			var client = new SalesforceClient(appId, secretKey);

			AuthenticationResult result;
			try
			{
				result = client.VerifyAuthentication(httpContext, this.MultiProtocolIssuer.ReplyUrl);
			}
			catch (WebException wex)
			{
				throw new InvalidOperationException(new StreamReader(wex.Response.GetResponseStream()).ReadToEnd(), wex);
			}

			var claims = new List<Claim>
				{
					new Claim(System.IdentityModel.Claims.ClaimTypes.NameIdentifier, result.ExtraData["id"])
				};

			foreach (var claim in result.ExtraData)
			{
				claims.Add(new Claim("http://schemas.live.com/" + claim.Key, claim.Value));
			}

			return new ClaimsIdentity(claims, "SalesForce");
		}
	}
}