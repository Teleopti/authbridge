using System;
using DotNetOpenAuth.AspNet.Clients;

namespace AuthBridge.Clients
{
	public class TeleoptiClient : OpenIdClient
	{
		public TeleoptiClient(Uri url)
			: base("Teleopti", url)
		{
		}
	}
}