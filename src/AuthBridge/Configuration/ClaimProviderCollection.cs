namespace AuthBridge.Configuration
{
    using System.Configuration;

    public class ClaimProviderCollection : ConfigurationElementCollection
    {
        public ClaimProviderElement this[int index] => (ClaimProviderElement)BaseGet(index);

	    public new ClaimProviderElement this[string key] => (ClaimProviderElement)BaseGet(key);

	    protected override ConfigurationElement CreateNewElement()
        {
            return new ClaimProviderElement();
        }

        protected override object GetElementKey(ConfigurationElement element)
        {
            return ((ClaimProviderElement)element).Name;
        }
    }
}