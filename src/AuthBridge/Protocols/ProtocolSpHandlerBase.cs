namespace AuthBridge.Protocols
{
	using System.Web;

    using Microsoft.IdentityModel.Claims;

    using Configuration;
    using Model;

	public abstract class ProtocolSpHandlerBase : ProtocolHandlerBase, IProtocolHandler
    {
		protected ProtocolSpHandlerBase(ClaimProvider issuer) : base(issuer)
		{
		}

		protected ProtocolSpHandlerBase(ClaimProvider issuer, IConfigurationRepository configuration) : base(issuer, configuration)
		{
		}

		public abstract void ProcessSignInRequest(Scope scope, HttpContextBase httpContext);

        public abstract IClaimsIdentity ProcessSignInResponse(string realm, string originalUrl, HttpContextBase httpContext);        
    }
}