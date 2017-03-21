using System;
using System.Collections.Generic;
using System.Net;
using System.Security.Claims;
using System.Web;
using AuthBridge.Clients.Util;
using AuthBridge.Model;
using log4net;
using ClaimTypes = System.IdentityModel.Claims.ClaimTypes;

namespace AuthBridge.Protocols.AWFOS
{
	public class AWFOSHandler : ProtocolHandlerBase
	{
		private readonly string _identityProviderSSOURL;
		private static readonly ILog Logger = LogManager.GetLogger(typeof(AWFOSHandler));
		
		public AWFOSHandler(ClaimProvider issuer)
			: base(issuer)
		{
			_identityProviderSSOURL = issuer.Parameters["identityProviderSSOURL"];
		}

		public override void ProcessSignInRequest(Scope scope, HttpContextBase httpContext)
		{
		}
		
		public override ClaimsIdentity ProcessSignInResponse(string realm, string originalUrl, HttpContextBase httpContext)
		{
			Logger.Info("ProcessSignInResponse");
			var token = httpContext.Request["ssoToken"];
			if (string.IsNullOrWhiteSpace(token)) throw new ArgumentException("The ssoToken cannot be empty. Please supply a valid token.", nameof(token));
			Logger.DebugFormat("The given token was {0}", token);

			var tokenRequest = WebRequest.Create(_identityProviderSSOURL);
			tokenRequest.ContentType = "text/json";
			tokenRequest.ContentLength = 0;
			tokenRequest.Method = "GET";
			tokenRequest.Headers.Add("authToken", token);
			
			var tokenResponse = (HttpWebResponse)tokenRequest.GetResponse();
			Logger.DebugFormat("tokenResponse.StatusCode {0}", tokenResponse);
			if (tokenResponse.StatusCode == HttpStatusCode.OK)
			{
				using (var responseStream = tokenResponse.GetResponseStream())
				{
					var tokenData = JsonHelper.Deserialize<AWFOSAccessTokenData>(responseStream);
					if (Logger.IsDebugEnabled)
					{
						Logger.DebugFormat("tokenData.Code {0}", tokenData.code);
						Logger.DebugFormat("tokenData.UserEmailId {0}", tokenData.userEmailId);
					}
					if (tokenData?.code == 2000 || tokenData?.code == 2010)
					{
						var claims = new List<Claim>
						{
							new Claim(ClaimTypes.NameIdentifier, tokenData.userEmailId)
						};
						return new ClaimsIdentity(claims, "AWFOS");
					}
				}
			}

			throw new InvalidOperationException("Not properly authenticated.");
		}
	}

	public class AWFOSAccessTokenData
	{
		public int code { get; set; }
		public string userEmailId { get; set; }
	}
}