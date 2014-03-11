using DotNetOpenAuth.AspNet.Clients;

namespace AuthBridge.Clients
{
	public class SalesForceOAuth2AccessTokenData : OAuth2AccessTokenData
	{
		public string id { get; set; }
	}
}