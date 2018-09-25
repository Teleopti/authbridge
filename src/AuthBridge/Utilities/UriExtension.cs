using System;
using System.Collections.Specialized;
using System.Web;

namespace AuthBridge.Utilities
{
	public static class UriExtension
	{
		public static Uri UrlConsideringLoadBalancerHeaders(this HttpRequestBase request)
		{
			var uri = request?.Url;
			if (uri == null) return null;
			if (uri.IsTransportSecure()) return uri;

			var headers = request.Headers;
			return considerLoadBalancerHeadersForScheme(headers, uri);
		}

		public static Uri UrlConsideringLoadBalancerHeaders(this HttpRequest request)
		{
			var uri = request?.Url;
			if (uri == null) return null;
			if (uri.IsTransportSecure()) return uri;

			var headers = request.Headers;
			return considerLoadBalancerHeadersForScheme(headers, uri);
		}

		public static bool IsTransportSecure(this Uri uri)
		{
			return string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);
		}

		private static Uri considerLoadBalancerHeadersForScheme(NameValueCollection headers, Uri uri)
		{
			if (headers == null) return uri;
			var forwardedProto = headers["X-Forwarded-Proto"];
			var frontEndHttps = headers["Front-End-Https"];
			if (Uri.UriSchemeHttps.Equals(forwardedProto, StringComparison.OrdinalIgnoreCase) ||
			    "on".Equals(frontEndHttps, StringComparison.OrdinalIgnoreCase))
			{
				var builder = new UriBuilder(uri)
				{
					Scheme = Uri.UriSchemeHttps,
					Port = 443
				};
				return builder.Uri;
			}

			return uri;
		}
	}
}