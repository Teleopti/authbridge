﻿using AuthBridge.Utilities;

namespace AuthBridge.Web.Controllers
{
    using System;
    using System.Web;

    public static class RequestUtilities
    {
        public static Uri GetRequestUrl(this HttpContextBase context)
        {
            var realHost = context.Request.Headers["HOST"];
            string url = context.Request.UrlConsideringLoadBalancerHeaders().Scheme + "://" + realHost + context.Request.RawUrl;

            return new Uri(url);            
        }

        public static Uri GetRealAppRoot(this HttpContextBase context)
        {
            var realHost = context.Request.Headers["HOST"];
            var requestUrl = context.Request.UrlConsideringLoadBalancerHeaders();
            Uri appRoot;

            if (realHost.Contains(":"))
            {
                var realHostParts = realHost.Split(':');
                appRoot = new UriBuilder(requestUrl.Scheme, realHostParts[0], Convert.ToInt32(realHostParts[1]), context.Request.ApplicationPath).Uri;
            }
            else
            {
                appRoot = new UriBuilder(requestUrl.Scheme, realHost, requestUrl.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase) ? 80 : 443, context.Request.ApplicationPath).Uri;
            }

            return appRoot;
        }
    }
}