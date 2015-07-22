using System;
using System.Collections.Generic;
using System.Web;
using AuthBridge.Clients;
using Microsoft.IdentityModel.Claims;
using AuthBridge.Model;
using System.Net;
using System.IO;
using DotNetOpenAuth.AspNet;

namespace AuthBridge.Protocols.OAuth
{
	public class AzureAdOAuthHandler : ProtocolHandlerBase
    {
        private readonly ClaimProvider issuer;
        private readonly string _appId;
        private readonly string _secretKey;
		private readonly string _graphApiEndpoint;
		private readonly string _tokenEndpoint;
		private readonly string _authorizationEndpoint;
		private readonly string _graphApiVersion;

		public AzureAdOAuthHandler(ClaimProvider issuer) : base(issuer)
        {
            if (issuer == null)
                throw new ArgumentNullException("issuer");

            this.issuer = issuer;
			_appId = this.issuer.Parameters["clientId"];
			_secretKey = this.issuer.Parameters["key"];
			_graphApiEndpoint = this.issuer.Parameters["graphApiEndpoint"];
			_tokenEndpoint = this.issuer.Parameters["tokenEndpoint"];
			_authorizationEndpoint = this.issuer.Parameters["authorizationEndpoint"];
			_graphApiVersion = this.issuer.Parameters["graphApiVersion"];
        }

        public override void ProcessSignInRequest(Scope scope, HttpContextBase httpContext)
        {
			var client = new AzureAdOAuthClient(_appId, _secretKey, _graphApiEndpoint, _tokenEndpoint, _authorizationEndpoint, _graphApiVersion);
            client.RequestAuthentication(httpContext, MultiProtocolIssuer.ReplyUrl);
        }

        public override IClaimsIdentity ProcessSignInResponse(string realm, string originalUrl, HttpContextBase httpContext)
        {
			var client = new AzureAdOAuthClient(_appId, _secretKey, _graphApiEndpoint, _tokenEndpoint, _authorizationEndpoint, _graphApiVersion);
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

			return new ClaimsIdentity(claims, "AzureAd");
        }      
    }
}