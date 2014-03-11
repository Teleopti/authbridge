using DotNetOpenAuth.AspNet.Clients;

namespace AuthBridge.Clients
{
	public class MyOpenIdClient : OpenIdClient
	{
		public MyOpenIdClient()
			: base("MyOpenId", "https://www.myopenid.com/")
		{
		}
	}
}