using System;
using System.Configuration;
using AuthBridge.Clients.Util;

namespace AuthBridge.Configuration
{
	public static class UriStringExtensions
	{
		public static Uri ReplaceWithLocalhostWhenRelative(this string uri)
		{
			var completeUri = new Uri(uri);
			if (ConfigurationManager.AppSettings.GetBoolSetting("UseRelativeConfiguration"))
			{
				completeUri = new Uri(new Uri(ConfigurationManager.AppSettings["CustomEndpointHost"] ?? "http://localhost/"),
					new Uri(completeUri.GetComponents(UriComponents.SchemeAndServer, UriFormat.Unescaped))
						.MakeRelativeUri(completeUri));
			}
			return completeUri;
		}
	}
}