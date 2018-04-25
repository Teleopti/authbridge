using System;
using System.Configuration;
using Microsoft.Practices.Unity;
using Microsoft.Practices.Unity.Configuration;

namespace AuthBridge.Configuration
{
	public static class ServiceLocator
	{
		public static Lazy<IUnityContainer> Container = new Lazy<IUnityContainer>(() =>
		{
			var unitySection = ConfigurationManager.GetSection("unity") as UnityConfigurationSection;
			if (unitySection == null)
			{
				throw new ArgumentException(nameof(unitySection));
			}
			var container = new UnityContainer();
			unitySection.Configure(container);
			return container;
		});
	}
}