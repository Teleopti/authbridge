namespace AuthBridge.Configuration
{
    using System;
    using AuthBridge.Model;

    public interface IConfigurationRepository
    {
        ClaimProvider RetrieveIssuer(Uri identifier);
        ClaimProvider[] RetrieveIssuers();

        Scope RetrieveScope(Uri identifier);

        MultiProtocolIssuer RetrieveMultiProtocolIssuer();
    }
}
