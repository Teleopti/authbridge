﻿namespace AuthBridge.Configuration
{
    using System.Configuration;

    public class AllowedClaimProviderElement : ConfigurationElement
    {
        [ConfigurationProperty("name", IsRequired = true, IsKey = true)]
        public string Name => (string)this["name"];
    }
}