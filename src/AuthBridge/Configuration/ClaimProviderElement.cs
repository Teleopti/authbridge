namespace AuthBridge.Configuration
{
	using System.Configuration;

    public class ClaimProviderElement : ConfigurationElement
    {
        [ConfigurationProperty("identifier", IsRequired = true, IsKey = true)]
        public string Name => (string)this["identifier"];

	    [ConfigurationProperty("displayName", IsRequired = true)]
		public string DisplayName => (string)this["displayName"];

	    [ConfigurationProperty("url", IsRequired = true)]
        public string Uri => (string)this["url"];

	    [ConfigurationProperty("realm", IsRequired = false)]
        public string Realm => (string)this["realm"];

	    [ConfigurationProperty("protocolHandler", IsRequired = true)]
        public string ProtocolHandler => (string)this["protocolHandler"];

	    [ConfigurationProperty("params", IsRequired = false)]
        [ConfigurationCollection(typeof(ParameterCollection))]
        public ParameterCollection Params => (ParameterCollection)this["params"];

	    [ConfigurationProperty("idpInitiatedOnly", IsRequired = false)]
		public bool IdpInitiatedOnly => (bool)this["idpInitiatedOnly"];
    }
}