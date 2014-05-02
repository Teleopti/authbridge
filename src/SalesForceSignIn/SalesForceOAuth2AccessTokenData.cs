using DotNetOpenAuth.AspNet.Clients;

namespace SalesForceSignIn
{
	public class SalesForceOAuth2AccessTokenData : OAuth2AccessTokenData
	{
		public string id { get; set; }
	}
}