namespace AuthBridge.Configuration
{
    using System.Configuration;

    public class ClaimRequirementElement : ConfigurationElement
    {
        [ConfigurationProperty("name", IsRequired = true)]
        public string Name => (string)this["name"];

	    [ConfigurationProperty("type", IsRequired = true, IsKey = true)]
        public string Type => (string)this["type"];

	    [ConfigurationProperty("demandLevel", IsRequired = true)]
        public string DemandLevel => (string)this["demandLevel"];
    }
}