using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Claims;
using System.Web;
using AuthBridge.Clients.Util;
using AuthBridge.Model;
using log4net;
using Newtonsoft.Json;
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

			var entity =
				JsonConvert.SerializeObject(
					new {ssoToken = httpContext.Request.QueryString["ssoToken"], tenant = httpContext.Request.QueryString["tenant"]});

			var tokenRequest = WebRequest.Create(_identityProviderSSOURL);
			tokenRequest.ContentType = "application/json";
			tokenRequest.ContentLength = entity.Length;
			tokenRequest.Method = "POST";

			using (var requestStream = tokenRequest.GetRequestStream())
			{
				var writer = new StreamWriter(requestStream);
				writer.Write(entity);
				writer.Flush();
			}

			var tokenResponse = (HttpWebResponse)tokenRequest.GetResponse();
			if (tokenResponse.StatusCode == HttpStatusCode.OK)
			{
				using (var responseStream = tokenResponse.GetResponseStream())
				{
					var tokenData = JsonHelper.Deserialize<AWFOSAccessTokenData>(responseStream);
					if (tokenData?.Code == 2000)
					{
						var claims = new List<Claim>
						{
							new Claim(ClaimTypes.NameIdentifier, tokenData.UserEmailId)
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
		public int Code { get; set; }
		public string UserEmailId { get; set; }
	}
}