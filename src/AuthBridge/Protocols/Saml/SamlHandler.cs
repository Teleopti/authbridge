using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Web;
using System.Xml;
using AuthBridge.Model;
using log4net;
using Microsoft.IdentityModel.Claims;

namespace AuthBridge.Protocols.Saml
{
	public class SamlHandler : ProtocolHandlerBase
	{
		private readonly string _signingKeyThumbprint;
		private readonly string _issuer;
		private readonly string _identityProviderSSOURL;
		private static readonly ILog Logger = LogManager.GetLogger(typeof(SamlHandler));


		public SamlHandler(ClaimProvider issuer)
			: base(issuer)
		{
			_signingKeyThumbprint = issuer.Parameters["signingKeyThumbprint"];
			_issuer = issuer.Parameters["issuer"];
			_identityProviderSSOURL = issuer.Parameters["identityProviderSSOURL"];
		}

		public override void ProcessSignInRequest(Scope scope, HttpContextBase httpContext)
		{
			var samlRequest = new AuthRequest(MultiProtocolIssuer.ReplyUrl.ToString(), _issuer);
			var preparedRequest = samlRequest.GetRequest(AuthRequest.AuthRequestFormat.Base64 | AuthRequest.AuthRequestFormat.Compressed | AuthRequest.AuthRequestFormat.UrlEncode);
			var returnUrl = GetReturnUrlQueryParameterFromUrl(httpContext.Request.Url.AbsoluteUri);
			httpContext.Response.Redirect(string.Format("{0}?SAMLRequest={1}&RelayState={2}", _identityProviderSSOURL, preparedRequest, returnUrl));

			httpContext.Response.End();
		}

		public override IClaimsIdentity ProcessSignInResponse(string realm, string originalUrl, HttpContextBase httpContext)
		{
			Logger.Info("ProcessSignInResponse");
			var response = Encoding.UTF8.GetString(Convert.FromBase64String(httpContext.Request.Form["SAMLResponse"]));
			Logger.Info(string.Format("SAMLResponse: {0}", response));
			var doc = new XmlDocument();
			doc.LoadXml(response);
			if (!VerifySignatures(doc))
			{
				throw new InvalidOperationException("The thumbprint doesn't match the white list values.");
			}
			Logger.Info("Verified signature succsessfully");

			var information = ExtractInformation(doc);
			Logger.Info(string.Format("extracted information: SubjectNameId: {0}, Issuer: {1}, NotBefore: {2}, NotOnOrAfter: {3}", information.SubjectNameId, information.Issuer, information.NotBefore, information.NotOnOrAfter));
			if (!VerifyAllowedDateTimeRange(information))
			{
				throw new InvalidOperationException("This SAML response is not valid any longer.");
			}
			Logger.Info("Verified allowed date time range succsessfully");

			//You must add a claims policy for the protocol identifier!
			var issuerIdentifier = information.Issuer;
			var claims = new List<Claim>
			{
				new Claim(System.IdentityModel.Claims.ClaimTypes.NameIdentifier, information.SubjectNameId)
			};
			return new ClaimsIdentity(claims, issuerIdentifier);
		}

		private static string GetReturnUrlQueryParameterFromUrl(string context)
		{
			var queryNameValueCollection = HttpUtility.ParseQueryString(context);

			var returnUrl = queryNameValueCollection["wctx"];
			if (!String.IsNullOrEmpty(returnUrl))
			{
				returnUrl = returnUrl.Replace("ru=", "");
				if (!returnUrl.EndsWith("/"))
					returnUrl += "/";
			}
			return returnUrl;
		}

		private static bool VerifyAllowedDateTimeRange(SamlDetail detail)
		{
			var now = DateTime.UtcNow;
			Logger.Info(string.Format("utcnow: {0}, detail.NotBefore: {1}, NotOnOrAfter: {2}, {3}, {4}", now, detail.NotBefore, detail.NotOnOrAfter, now >= detail.NotBefore, now < detail.NotOnOrAfter));
			return now >= detail.NotBefore && now < detail.NotOnOrAfter;
		}

		private static SamlDetail ExtractInformation(XmlDocument doc)
		{
			var detail = new SamlDetail();
			var conditionsElement = doc.SelectSingleNode("//*[local-name()='Conditions']");
			if (conditionsElement != null)
			{
				detail.NotBefore = XmlConvert.ToDateTime(conditionsElement.Attributes["NotBefore"].Value, XmlDateTimeSerializationMode.Utc);
				detail.NotOnOrAfter = XmlConvert.ToDateTime(conditionsElement.Attributes["NotOnOrAfter"].Value, XmlDateTimeSerializationMode.Utc);
			}

			var nameIdElement = doc.SelectSingleNode("//*[local-name()='Subject']/*[local-name()='NameID']");
			detail.SubjectNameId = nameIdElement.InnerText;

			var issuerElement = doc.SelectSingleNode("//*[local-name()='Issuer']");
			detail.Issuer = issuerElement.InnerText;

			return detail;
		}

		private bool VerifySignatures(XmlDocument xmlDoc)
		{
			foreach (XmlElement node in xmlDoc.SelectNodes("//*[local-name()='Signature']"))
			{
				var doc = new XmlDocument();
				doc.LoadXml(node.ParentNode.OuterXml);

				var signedXml = new SignedXml(node.ParentNode as XmlElement);
				signedXml.LoadXml(node);

				var x509Data = signedXml.Signature.KeyInfo.OfType<KeyInfoX509Data>().First();
				var cert = x509Data.Certificates.OfType<X509Certificate2>().First();
				if (cert.Thumbprint != null && cert.Thumbprint.Equals(_signingKeyThumbprint, StringComparison.InvariantCultureIgnoreCase))
					return true;
			}
			return false;
		}

		
	}
}