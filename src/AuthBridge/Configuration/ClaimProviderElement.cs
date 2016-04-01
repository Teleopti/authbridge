namespace AuthBridge.Configuration
{
    using System;
    using System.Configuration;

    public class ClaimProviderElement : ConfigurationElement
    {
        [ConfigurationProperty("identifier", IsRequired = true, IsKey = true)]
        public string Name
        {
            get { return (string)this["identifier"]; }
        }

		[ConfigurationProperty("displayName", IsRequired = true)]
		public string DisplayName
		{
			get { return (string)this["displayName"]; }
		}

        [ConfigurationProperty("url", IsRequired = true)]
        public string Uri
        {
            get { return (string)this["url"]; }
        }

        [ConfigurationProperty("realm", IsRequired = false)]
        public string Realm
        {
            get { return (string)this["realm"]; }
        }

        [ConfigurationProperty("protocolHandler", IsRequired = true)]
        public string ProtocolHandler
        {
            get { return (string)this["protocolHandler"]; }
        }

        [ConfigurationProperty("params", IsRequired = false)]
        [ConfigurationCollection(typeof(ParameterCollection))]
        public ParameterCollection Params
        {
            get { return (ParameterCollection)this["params"]; }
        }

		[ConfigurationProperty("idpInitiatedOnly", IsRequired = false)]
		public bool IdpInitiatedOnly
		{
			get { return (bool)this["idpInitiatedOnly"]; }
		}
    }
}