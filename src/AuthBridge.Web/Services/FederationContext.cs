using AuthBridge.Utilities;

namespace AuthBridge.Web.Services
{
    using System.Web;
    using System;

    public class FederationContext : IFederationContext
    {
        // TODO: sign context cookie to avoid tampering with its values

        public string Realm
        {
            get { return HttpUtility.UrlDecode(GetValue("wtrealm")); }
            set { SetValue("wtrealm", HttpUtility.UrlEncode(value)); }
        }

        public string OriginalUrl
        {
            get { return HttpUtility.UrlDecode(this.GetValue("originalUrl")); }
            set { SetValue("originalUrl", HttpUtility.UrlEncode(value)); }
        }

        public string IssuerName
        {
            get { return GetValue("issuerName"); }
            set { SetValue("issuerName", value); }
        }

        public string Context
        {
            get { return GetValue("wctx"); }
            set { SetValue("wctx", value); }
        }

        private static HttpCookie FederationCookie
        {
            get
            {
                var cookie = HttpContext.Current.Request.Cookies.Get("FederationContext");

                if (cookie == null)
                {
                    cookie = new HttpCookie("FederationContext")
                    {
                        HttpOnly = true,
                        Secure = HttpContext.Current.Request.UrlConsideringLoadBalancerHeaders().IsTransportSecure()
                    };
                    HttpContext.Current.Response.Cookies.Add(cookie);
                }

                return cookie;
            }
        }

        public string GetValue(string key)
        {
            return FederationCookie.Values[key];
        }

        public void SetValue(string key, string value)
        {
            FederationCookie.Values[key] = value;
            HttpContext.Current.Response.Cookies.Set(FederationCookie);
        }

        public void Destroy()
        {
            FederationCookie.Expires = DateTime.Now.AddDays(-1);
            HttpContext.Current.Response.Cookies.Add(FederationCookie);
        }
    }
}