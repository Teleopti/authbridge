using System;
using System.Globalization;
using System.Reflection;
using System.Web;
using DotNetOpenAuth.OpenId;
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
			
			var site = new Uri("http://localhost");
			var userSuppliedIdentifierForRequestMachine = new Uri(site,
				new Uri(userSuppliedIdentifier.GetComponents(UriComponents.SchemeAndServer, UriFormat.Unescaped)).MakeRelativeUri(userSuppliedIdentifier));
			Logger.InfoFormat("Request {0}; userSuppliedIdentifier {1}", request, userSuppliedIdentifier);
			Logger.InfoFormat("Request {0}; userSuppliedIdentifierForRequestMachine {1}", request, userSuppliedIdentifierForRequestMachine);
			IAuthenticationRequest authenticationRequest = relyingParty.CreateRequest(userSuppliedIdentifierForRequestMachine, realm, returnUrl);
			OnBeforeSendingAuthenticationRequest(authenticationRequest);

			var property = authenticationRequest.DiscoveryResult.GetType()
				.GetProperty("UserSuppliedIdentifier", BindingFlags.Instance | BindingFlags.NonPublic);

			site = new Uri(context.Request.Url.GetComponents(UriComponents.SchemeAndServer, UriFormat.Unescaped));
			var userSupplied = new Uri(site,
				new Uri(userSuppliedIdentifier.GetComponents(UriComponents.SchemeAndServer, UriFormat.Unescaped)).MakeRelativeUri(userSuppliedIdentifier));

			Logger.InfoFormat("Request {0}; userSupplied {1}", request, userSupplied);

			property.SetValue(authenticationRequest.DiscoveryResult, userSupplied, BindingFlags.SetProperty | BindingFlags.NonPublic, null, null, CultureInfo.CurrentCulture);
			authenticationRequest.RedirectToProvider();
		}
	}
}