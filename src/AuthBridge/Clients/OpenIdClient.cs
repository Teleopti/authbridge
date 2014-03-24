using System;
using DotNetOpenAuth.AspNet.Clients;

namespace AuthBridge.Clients
{
	public class OpenIdClient : DotNetOpenAuth.AspNet.Clients.OpenIdClient
	{
		public OpenIdClient(Uri url)
			: base("Windows", url)
		{
		}
	}
}