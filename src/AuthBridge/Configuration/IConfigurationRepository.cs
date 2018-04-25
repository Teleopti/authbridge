namespace AuthBridge.Configuration
{
    using System;
    using Model;

    public interface IConfigurationRepository
    {
	    ClaimProvider RetrieveIssuer(Uri host, Uri identifier);
        ClaimProvider[] RetrieveIssuers(Uri host);

        Scope RetrieveScope(Uri host, Uri identifier);

	    MultiProtocolIssuer MultiProtocolIssuer { get; }

	    ScopeElement RetrieveDefaultScope(Uri host);
    }
}
