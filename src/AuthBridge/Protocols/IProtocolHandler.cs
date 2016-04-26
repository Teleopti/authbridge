using System.Security.Claims;

namespace AuthBridge.Protocols
{
	using System.Web;
    using AuthBridge.Model;

    public interface IProtocolHandler
    {
        void ProcessSignInRequest(Scope scope, HttpContextBase httpContext);

		ClaimsIdentity ProcessSignInResponse(string realm, string originalUrl, HttpContextBase httpContext);
    }
}