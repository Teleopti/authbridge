using System;
using DotNetOpenAuth.AspNet.Clients;

namespace AuthBridge.Clients
{
	public class WindowsClient : OpenIdClient
	{
		public WindowsClient(Uri url)
			: base("Windows", url)
		{
		}
	}
}