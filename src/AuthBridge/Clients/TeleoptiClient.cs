using DotNetOpenAuth.AspNet.Clients;

namespace AuthBridge.Clients
{
	public class TeleoptiClient : OpenIdClient
	{
		public TeleoptiClient()
			: base("Teleopti", "http://localhost:4864/")
		{
		}
	}
}