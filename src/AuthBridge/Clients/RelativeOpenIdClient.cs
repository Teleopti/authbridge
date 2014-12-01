using System;
using System.Collections.Generic;
using System.Globalization;
using System.Reflection;
using System.Web;
using DotNetOpenAuth.OpenId;
using DotNetOpenAuth.OpenId.Messages;
using DotNetOpenAuth.OpenId.RelyingParty;
using log4net;

namespace AuthBridge.Clients
{
	public class RelativeOpenIdClient : DotNetOpenAuth.AspNet.Clients.OpenIdClient
	{
		private static readonly ILog Logger = LogManager.GetLogger(typeof (RelativeOpenIdClient));
		private readonly Uri _realmUri;

		public RelativeOpenIdClient(Uri url, Uri realmUri)
			: base("Relative", url)
		{
			_realmUri = realmUri;
		}

		public override void RequestAuthentication(HttpContextBase context, Uri returnUrl)
		{
			var request = Guid.NewGuid();
			var relyingPartyField = typeof(DotNetOpenAuth.AspNet.Clients.OpenIdClient).GetField("RelyingParty",
				BindingFlags.Static | BindingFlags.NonPublic);
			var providerIdentifierField = typeof(DotNetOpenAuth.AspNet.Clients.OpenIdClient).GetField(
				"providerIdentifier", BindingFlags.NonPublic | BindingFlags.Instance);
			var relyingParty = (OpenIdRelyingParty)relyingPartyField.GetValue(this);
			var realm = new Realm(_realmUri ?? new Uri(returnUrl.GetComponents(UriComponents.SchemeAndServer, UriFormat.Unescaped)));
			var userSuppliedIdentifier = new Uri((Identifier)providerIdentifierField.GetValue(this));
			var localhost = new Uri("http://localhost");
			var userSuppliedIdentifierForRequestMachine = new Uri(localhost,
				new Uri(userSuppliedIdentifier.GetComponents(UriComponents.SchemeAndServer, UriFormat.Unescaped)).MakeRelativeUri(userSuppliedIdentifier));

			Logger.InfoFormat("Request {0}; userSuppliedIdentifier {1}; userSuppliedIdentifierForRequestMachine {2}", request, userSuppliedIdentifier, userSuppliedIdentifierForRequestMachine);
			IAuthenticationRequest authenticationRequest = relyingParty.CreateRequest(userSuppliedIdentifierForRequestMachine, realm, returnUrl);
			OnBeforeSendingAuthenticationRequest(authenticationRequest);

			try
			{
				var property = authenticationRequest.DiscoveryResult.GetType().GetProperty("ProviderEndpoint");
				
				Logger.InfoFormat("Request {0}; userSupplied {1}", request, userSuppliedIdentifier);
				property.SetValue(authenticationRequest.DiscoveryResult, userSuppliedIdentifier, BindingFlags.SetProperty, null, null, CultureInfo.CurrentCulture);
				
				authenticationRequest.RedirectToProvider();
			}
			catch (Exception ex)
			{
				Logger.Error("Error in discovery modification", ex);
				throw;
			}
		}
	}
}