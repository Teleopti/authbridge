using System;
using System.Collections.Specialized;

namespace AuthBridge.Clients.Util
{
	public static class ConfigurationExtensions
	{
		public static bool GetBoolSetting(this NameValueCollection configuration, string key, Func<bool> ifNotFound = null)
		{
			ifNotFound = ifNotFound ?? (() => false);
			var value = configuration.Get(key);
			bool result;
			return string.IsNullOrEmpty(value) ? ifNotFound() : (bool.TryParse(value, out result) ? result : ifNotFound());
		}
	}
}