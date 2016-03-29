using System;
using System.Collections.Generic;
using System.Text;
using System.Web;
using System.Xml;
using AuthBridge.Model;
using Microsoft.IdentityModel.Claims;

namespace AuthBridge.Protocols.OpenID
{
	public class SamlDetail
	{
		public string Issuer { get; set; }
		public string SubjectNameId { get; set; }
		public DateTime NotBefore { get; set; }
		public DateTime NotOnOrAfter { get; set; }
	}

	public class SamlIdpHandler : ProtocolHandlerBase
	{
		public SamlIdpHandler(ClaimProvider issuer)
			: base(issuer)
		{
		}

		public override void ProcessSignInRequest(Scope scope, HttpContextBase httpContext)
		{
			// not needed for idp
		}

		public override IClaimsIdentity ProcessSignInResponse(string realm, string originalUrl, HttpContextBase httpContext)
		{
			var response = Encoding.UTF8.GetString(Convert.FromBase64String(httpContext.Request.Form["SAMLResponse"]));
			var doc = new XmlDocument();
			doc.LoadXml(response);
			if (!VerifySignaturesShouldWorkButIHadSomeIssuesWithReferences(doc))
			{
				throw new InvalidOperationException("The thumbprint doesn't match the white list values.");
			}

			var information = ExtractInformation(doc);
			if (!VerifyAllowedDateTimeRange(information))
			{
				throw new InvalidOperationException("This SAML response is not valid any longer.");
			}

			//You must add a claims policy for the protocol identifier!
			var issuerIdentifier = information.Issuer;
			var claims = new List<Claim>
		    {
			    new Claim(System.IdentityModel.Claims.ClaimTypes.NameIdentifier, information.SubjectNameId)
		    };
			return new ClaimsIdentity(claims, issuerIdentifier);
		}

		private static bool VerifyAllowedDateTimeRange(SamlDetail detail)
		{
			var now = DateTime.Now;
			return now >= detail.NotBefore && now < detail.NotOnOrAfter;
		}

		private static SamlDetail ExtractInformation(XmlDocument doc)
		{
			var detail = new SamlDetail();
			var conditionsElement = doc.SelectSingleNode("//*[local-name()='Conditions']");
			detail.NotBefore = XmlConvert.ToDateTime(conditionsElement.Attributes["NotBefore"].Value);
			detail.NotOnOrAfter = XmlConvert.ToDateTime(conditionsElement.Attributes["NotOnOrAfter"].Value);

			var nameIdElement = doc.SelectSingleNode("//*[local-name()='Subject']/*[local-name()='NameID']");
			detail.SubjectNameId = nameIdElement.InnerText;

			var issuerElement = doc.SelectSingleNode("//*[local-name()='Issuer']");
			detail.Issuer = issuerElement.InnerText;

			return detail;
		}

		private static bool VerifySignaturesShouldWorkButIHadSomeIssuesWithReferences(XmlDocument xmlDoc)
		{
			return true;
			/*
			foreach (XmlElement node in xmlDoc.SelectNodes("//*[local-name()='Signature']"))
			{
				XmlDocument doc = new XmlDocument();
				doc.LoadXml(node.ParentNode.OuterXml);

				SignedXml signedXml = new SignedXml(node.ParentNode as XmlElement);
				signedXml.LoadXml(node);

				var x509Data = signedXml.Signature.KeyInfo.OfType<KeyInfoX509Data>().First();
				var cert = x509Data.Certificates.OfType<X509Certificate2>().First();
				if (string.Compare(cert.Thumbprint, 0, "0fe81e3a29534b7a8427b380dfee673d032342e5", 0, cert.Thumbprint.Length, true) == 0)
					return true;
			}
			return false;
			*/
		}

	}
}