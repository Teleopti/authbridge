using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Claims;
using System.Web;
using AuthBridge.Clients;
using AuthBridge.Model;
using DotNetOpenAuth.AspNet;

namespace AuthBridge.Protocols.OAuth
{
	public class GoogleHandler : ProtocolHandlerBase
	{
		private readonly ClaimProvider _issuer;
		private readonly string _clientSecret;
		private readonly string _clientId;
		private readonly string _prompt;

		public GoogleHandler(ClaimProvider issuer) : base(issuer)
		{
			if (issuer == null)
				throw new ArgumentNullException(nameof(issuer));
			_issuer = issuer;
			_clientId = _issuer.Parameters["clientId"];
			_clientSecret = _issuer.Parameters["clientSecret"];
			_prompt = _issuer.Parameters["prompt"];
		}

		public override void ProcessSignInRequest(Scope scope, HttpContextBase httpContext)
		{
			var client = new GoogleOAuthClient(_clientId, _clientSecret, _prompt);
			client.RequestAuthentication(httpContext, MultiProtocolIssuer.ReplyUrl);
		}

		public override ClaimsIdentity ProcessSignInResponse(string realm, string originalUrl, HttpContextBase httpContext)
		{
			var client = new GoogleOAuthClient(_clientId, _clientSecret, _prompt);
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
				new Claim(ClaimTypes.NameIdentifier, result.ExtraData["email"])
			};

			return new ClaimsIdentity(claims, "Google");
		}
	}
}