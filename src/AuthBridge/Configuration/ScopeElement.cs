namespace AuthBridge.Configuration
{
    using System.Configuration;

    public class ScopeElement : ConfigurationElement
    {
        [ConfigurationProperty("identifier", IsRequired = true)]
        public string Identifier => (string)this["identifier"];

	    [ConfigurationProperty("uri", IsRequired = true, IsKey = true)]
        public string Uri => (string)this["uri"];

	    [ConfigurationProperty("useClaimsPolicyEngine", IsRequired = false, DefaultValue = false)]
        public bool UseClaimsPolicyEngine => (bool)this["useClaimsPolicyEngine"];

	    [ConfigurationProperty("useRelativeUri", IsRequired = false, DefaultValue = true)]
	    public bool UseRelativeUri => (bool)this["useRelativeUri"];

		[ConfigurationProperty("claimRequirements", IsDefaultCollection = false)]
        [ConfigurationCollection(typeof(ClaimRequirementCollection))]
        public ClaimRequirementCollection ClaimRequirements => (ClaimRequirementCollection)base["claimRequirements"];

	    [ConfigurationProperty("allowedClaimProviders", IsDefaultCollection = false)]
        [ConfigurationCollection(typeof(AllowedClaimProviderCollection))]
        public AllowedClaimProviderCollection Issuers => (AllowedClaimProviderCollection)base["allowedClaimProviders"];
    }
}