namespace AuthBridge.Configuration
{
    using System;
    using Model;

    public interface IConfigurationRepository
    {
	    ClaimProvider RetrieveIssuer(Uri identifier);
        ClaimProvider[] RetrieveIssuers();

        Scope RetrieveScope(Uri identifier);

	    MultiProtocolIssuer MultiProtocolIssuer { get; }

	    ScopeElement RetrieveDefaultScope();
    }
}
