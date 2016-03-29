using System;
using AuthBridge.Configuration;
using AuthBridge.Model;

namespace AuthBridge.Protocols
{
	public abstract class ProtocolHandlerBase
	{
		protected ProtocolHandlerBase(ClaimProvider issuer) : this(issuer, DefaultConfigurationRepository.Instance)
		{
		}

		protected ProtocolHandlerBase(ClaimProvider issuer, IConfigurationRepository configuration)
		{
			if (issuer == null)
				throw new ArgumentNullException("issuer");

			if (configuration == null)
				throw new ArgumentNullException("configuration");

			this.Issuer = issuer;
			this.Configuration = configuration;
			this.MultiProtocolIssuer = this.Configuration.MultiProtocolIssuer;              
		}

		protected ClaimProvider Issuer { get; set; }

		protected IConfigurationRepository Configuration { get; set; }

		protected MultiProtocolIssuer MultiProtocolIssuer { get; set; }
	}
}