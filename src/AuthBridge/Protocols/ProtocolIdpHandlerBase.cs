using System.Web;
using AuthBridge.Configuration;
using AuthBridge.Model;
using Microsoft.IdentityModel.Claims;

namespace AuthBridge.Protocols
{
	public abstract class ProtocolIdpHandlerBase : ProtocolHandlerBase, IProtocolIdpHandler
	{
		protected ProtocolIdpHandlerBase(ClaimProvider issuer) : base(issuer)
		{
		}

		protected ProtocolIdpHandlerBase(ClaimProvider issuer, IConfigurationRepository configuration) : base(issuer, configuration)
		{
		}

		public abstract IClaimsIdentity ProcessIdpInitiatedRequest(HttpContextBase httpContext);
	}
}