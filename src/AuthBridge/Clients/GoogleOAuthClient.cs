using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using DotNetOpenAuth.AspNet.Clients;
using DotNetOpenAuth.Messaging;

namespace AuthBridge.Clients
{
	public class GoogleOAuthClient : OAuth2Client
	{
		private readonly string _clientId;
		private readonly string _clientSecret;
		private string _authorizationEndpoint= "https://accounts.google.com/o/oauth2/auth";
		private string _tokenEndpoint = "https://accounts.google.com/o/oauth2/token";
		private string _userInfoEndpoint = "https://www.googleapis.com/oauth2/v1/userinfo";

		public GoogleOAuthClient(string clientId, string clientSecret):this("GoogleOAuthClient", clientId, clientSecret)
		{
		}

		public GoogleOAuthClient(string providerName, string clientId, string clientSecret) : base(providerName)
		{
			this._clientId = clientId;
			this._clientSecret = clientSecret;
		}

		protected override Uri GetServiceLoginUrl(Uri returnUrl)
		{
			var builder = new UriBuilder(_authorizationEndpoint);
			builder.AppendQueryArgs(
				new Dictionary<string, string>
				{
					{"response_type", "code"},
					{"redirect_uri", returnUrl.AbsoluteUri},
					{"scope", "https://www.googleapis.com/auth/userinfo.email"},
					{"client_id", _clientId}
				});

			return builder.Uri;
		}

		protected override IDictionary<string, string> GetUserData(string accessToken)
		{
			GoogleUserData graph;
			var request = WebRequest.Create($"{_userInfoEndpoint}");
			request.Headers.Add(HttpRequestHeader.Authorization.ToString(), $"Bearer {accessToken}");
			using (var response = request.GetResponse())
			{
				using (var responseStream = response.GetResponseStream())
				{
					graph = JsonHelper.Deserialize<GoogleUserData>(responseStream);
				}
			}

			var userData = new Dictionary<string, string>();
			userData.AddItemIfNotEmpty("id", graph.id);
			userData.AddItemIfNotEmpty("name", graph.name);
			userData.AddItemIfNotEmpty("given_name", graph.given_name);
			userData.AddItemIfNotEmpty("email", graph.email);
			return userData;
		}

		protected override string QueryAccessToken(Uri returnUrl, string authorizationCode)
		{
			var entity =
				MessagingUtilities.CreateQueryString(
					new Dictionary<string, string>
					{
						{"client_id", _clientId},
						{"redirect_uri", returnUrl.AbsoluteUri},
						{"client_secret", _clientSecret},
						{"code", authorizationCode},
						{"grant_type", "authorization_code"}
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

	public class GoogleUserData
	{
		public string id { get; set; }
		public string name { get; set; }
		public string given_name { get; set; }
		public string email { get; set; }
	}
}