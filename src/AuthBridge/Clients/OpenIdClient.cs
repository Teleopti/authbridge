using System;
using System.Collections.Generic;
using System.Reflection;
using System.Security.Claims;
using System.Web;
using AuthBridge.Clients.Util;
using DotNetOpenAuth.OpenId;
using DotNetOpenAuth.OpenId.Extensions.AttributeExchange;
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

		protected override Dictionary<string, string> GetExtraData(IAuthenticationResponse response)
		{
			var fetchResponse = response.GetExtension<FetchResponse>();
			if (fetchResponse != null)
			{
				var extraData = new Dictionary<string, string>();
				extraData.AddItemIfNotEmpty(ClaimTypes.IsPersistent, fetchResponse.GetAttributeValue(ClaimTypes.IsPersistent));

				return extraData;
			}
			return null;
		}
	}
}