using System;
using System.Reflection;
using System.Web;
using DotNetOpenAuth.OpenId;
using DotNetOpenAuth.OpenId.RelyingParty;

namespace AuthBridge.Clients
{
	public class OpenIdClient : DotNetOpenAuth.AspNet.Clients.OpenIdClient
	{
	    private readonly Uri _realmUri;

	    public OpenIdClient(Uri url, Uri realmUri)
			: base("Windows", url)
		{
		    _realmUri = realmUri;
		}

	    public override void RequestAuthentication(HttpContextBase context, Uri returnUrl)
	    {
	        var relyingPartyField = typeof (DotNetOpenAuth.AspNet.Clients.OpenIdClient).GetField("RelyingParty",
	            BindingFlags.Static | BindingFlags.NonPublic);
	        var providerIdentifierField = typeof (DotNetOpenAuth.AspNet.Clients.OpenIdClient).GetField(
	            "providerIdentifier", BindingFlags.NonPublic | BindingFlags.Instance);
	        var relyingParty = (OpenIdRelyingParty)relyingPartyField.GetValue(this);
            Realm realm = new Realm(_realmUri ?? new Uri(returnUrl.GetComponents(UriComponents.SchemeAndServer, UriFormat.Unescaped)));
            IAuthenticationRequest authenticationRequest = relyingParty.CreateRequest((Identifier) providerIdentifierField.GetValue(this), realm, returnUrl);
            this.OnBeforeSendingAuthenticationRequest(authenticationRequest);
            authenticationRequest.RedirectToProvider();
	    }
	}
}