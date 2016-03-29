using System.Web;
using Microsoft.IdentityModel.Claims;

namespace AuthBridge.Protocols
{
	public interface IProtocolIdpHandler
	{
		IClaimsIdentity ProcessIdpInitiatedRequest(HttpContextBase httpContext);
	}
}