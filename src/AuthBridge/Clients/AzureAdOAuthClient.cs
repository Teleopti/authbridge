using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using AuthBridge.Clients.Util;
using DotNetOpenAuth.AspNet.Clients;

namespace AuthBridge.Clients
{
	public class AzureAdOAuthClient : OAuth2Client
	{
		private readonly string _authorizationEndpoint;
		private readonly string _tokenEndpoint;
		private readonly string _graphApiEndpoint;
		private readonly string _graphApiVersion;

		private const string GraphApiResource = "https://graph.windows.net";

		private readonly string _appId;
		private readonly string _appSecret;

		public AzureAdOAuthClient(string appId, string secretKey, string graphApiEndpoint, string tokenEndpoint, string authorizationEndpoint, string graphApiVersion)
			: this("AzureAdOAuth", appId, secretKey, graphApiEndpoint, tokenEndpoint, authorizationEndpoint, graphApiVersion)
		{
		}

		protected AzureAdOAuthClient(string providerName, string appId, string appSecret, string graphApiEndpoint, string tokenEndpoint, string authorizationEndpoint, string graphApiVersion)
			: base(providerName)
		{
			_appId = appId;
			_appSecret = appSecret;
			_graphApiEndpoint = graphApiEndpoint;
			_tokenEndpoint = tokenEndpoint;
			_authorizationEndpoint = authorizationEndpoint;
			_graphApiVersion = graphApiVersion;
		}

		protected override Uri GetServiceLoginUrl(Uri returnUrl)
		{
			var builder = new UriBuilder(_authorizationEndpoint);
			builder.AppendQueryArgs(
				new Dictionary<string, string> {
					{ "client_id", _appId },
					{ "response_type", "code" },
					{ "redirect_uri", returnUrl.AbsoluteUri },
				});

			return builder.Uri;
		}

		protected override IDictionary<string, string> GetUserData(string accessToken)
		{
			AzureAdUserData graph;
			var request = WebRequest.Create($"{_graphApiEndpoint}/me?api-version={_graphApiVersion}");
			request.Headers.Add(HttpRequestHeader.Authorization.ToString(), $"Bearer {accessToken}");
			using (var response = request.GetResponse())
			{
				using (var responseStream = response.GetResponseStream())
				{
					graph = JsonHelper.Deserialize<AzureAdUserData>(responseStream);
				}
			}

			var userData = new Dictionary<string, string>();
			userData.AddItemIfNotEmpty("id", graph.userPrincipalName);
			userData.AddItemIfNotEmpty("objectId", graph.objectId);
			userData.AddItemIfNotEmpty("username", graph.userPrincipalName);
			userData.AddItemIfNotEmpty("name", graph.displayName);
			return userData;
		}

		protected override string QueryAccessToken(Uri returnUrl, string authorizationCode)
		{
			var entity =
				MessagingUtilities.CreateQueryString(
					new Dictionary<string, string> {
						{ "client_id", _appId },
						{ "redirect_uri", returnUrl.AbsoluteUri },
						{ "client_secret", _appSecret },
						{ "code", authorizationCode },
						{ "grant_type", "authorization_code" },
						{"resource",GraphApiResource}
					});

			var tokenRequest = WebRequest.Create(_tokenEndpoint);
			tokenRequest.ContentType = "application/x-www-form-urlencoded";
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
					var tokenData = JsonHelper.Deserialize<OAuth2AccessTokenData>(responseStream);
					if (tokenData != null)
					{
						return tokenData.AccessToken;
					}
				}
			}

			return null;
		}
	}

	public class AzureAdUserData
	{
		public string objectId;
		public string userPrincipalName;
		public string displayName;
	}
}