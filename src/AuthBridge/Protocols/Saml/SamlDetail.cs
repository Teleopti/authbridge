using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Web;
using System.Xml;

namespace AuthBridge.Protocols.Saml
{
	public class SamlDetail
	{
		public string Issuer { get; set; }
		public string SubjectNameId { get; set; }
		public DateTime NotBefore { get; set; }
		public DateTime NotOnOrAfter { get; set; }
		public List<string> AudienceRestrictions { get; set; }

		public SamlDetail()
		{
			NotBefore = DateTime.MinValue;
			NotOnOrAfter = DateTime.MaxValue;
		}
	}

	public static class Saml2Constants
	{
		public const string Protocol = "urn:oasis:names:tc:SAML:2.0:protocol";
		public const string Assertion = "urn:oasis:names:tc:SAML:2.0:assertion";
		public const string PostBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
	}

	public class AuthRequest
	{
		public string Id;
		private readonly string _issueInstant;
		private readonly string _assertionConsumerServiceUrl;
		private readonly string _issuer;
		private readonly string _audienceRestriction;
		private readonly string _requestedAuthnContextComparisonMethod;
		private readonly List<string> _authnContextClassRefs;

		[Flags]
		public enum AuthRequestFormat
		{
			Base64 = 1,
			Compressed = 2,
			UrlEncode = 4
		}

		public AuthRequest(string assertionConsumerServiceUrl, string issuer, string audienceRestriction, string requestedAuthnContextComparisonMethod, List<string> authnContextClassRefs)
		{
			_assertionConsumerServiceUrl = assertionConsumerServiceUrl;
			_issuer = issuer;
			_audienceRestriction = audienceRestriction;
			Id = "_" + Guid.NewGuid();
			_issueInstant = DateTime.Now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ");

			_requestedAuthnContextComparisonMethod = string.IsNullOrWhiteSpace(requestedAuthnContextComparisonMethod)
				? "minimum"
				: requestedAuthnContextComparisonMethod;
			
			if (authnContextClassRefs == null || !authnContextClassRefs.Any())
				authnContextClassRefs = DefaultAuthnContextClassRefs();
			_authnContextClassRefs = authnContextClassRefs;
		}

		public string GetRequest(AuthRequestFormat format)
		{
			

			using (var sw = new StringWriter())
			{
				var xws = new XmlWriterSettings {OmitXmlDeclaration = true};
				using (var xw = XmlWriter.Create(sw, xws))
				{
					xw.WriteStartElement("samlp", "AuthnRequest", Saml2Constants.Protocol);
					xw.WriteAttributeString("ID", Id);
					xw.WriteAttributeString("Version", "2.0");
					xw.WriteAttributeString("IssueInstant", _issueInstant);
					xw.WriteAttributeString("ProtocolBinding", Saml2Constants.PostBinding);
					xw.WriteAttributeString("AssertionConsumerServiceURL", _assertionConsumerServiceUrl);

					xw.WriteStartElement("saml", "Issuer", Saml2Constants.Assertion);
					xw.WriteString(_issuer);
					xw.WriteEndElement();

					xw.WriteStartElement("samlp", "NameIDPolicy", Saml2Constants.Protocol);
					xw.WriteAttributeString("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
					xw.WriteAttributeString("AllowCreate", "true");
					xw.WriteEndElement();

					if (!string.IsNullOrEmpty(_audienceRestriction))
					{
						xw.WriteStartElement("saml", "Conditions", Saml2Constants.Assertion);
						xw.WriteStartElement("saml", "AudienceRestriction", Saml2Constants.Assertion);
						xw.WriteStartElement("saml", "Audience", Saml2Constants.Assertion);
						xw.WriteString(_audienceRestriction);
						xw.WriteEndElement();
						xw.WriteEndElement();
						xw.WriteEndElement();
					}

					xw.WriteStartElement("samlp", "RequestedAuthnContext", Saml2Constants.Protocol);
					xw.WriteAttributeString("Comparison", _requestedAuthnContextComparisonMethod);

					foreach (var authnContextClassRef in _authnContextClassRefs)
					{
						xw.WriteStartElement("saml", "AuthnContextClassRef", Saml2Constants.Assertion);
						xw.WriteString(authnContextClassRef);
						xw.WriteEndElement();
					}

					xw.WriteEndElement();

					xw.WriteEndElement();
				}
				var result = sw.ToString();
				byte[] compressedBytes = null;
				if (format.HasFlag(AuthRequestFormat.Compressed))
				{
					compressedBytes = Compress(result);
				}
				if (format.HasFlag(AuthRequestFormat.Base64))
				{
					result = Convert.ToBase64String(compressedBytes ?? Encoding.ASCII.GetBytes(result));
				}
				if (format.HasFlag(AuthRequestFormat.UrlEncode))
				{
					result = HttpUtility.UrlEncode(result);
				}

				return result;
			}
		}

		private static byte[] Compress(string request)
		{
			var bytes = Encoding.ASCII.GetBytes(request);
			using (var output = new MemoryStream())
			{
				using (var zip = new DeflateStream(output, CompressionMode.Compress))
				{
					zip.Write(bytes, 0, bytes.Length);
				}
				return output.ToArray();
			}
		}

		private static List<string> DefaultAuthnContextClassRefs()
		{
			return new[]
				{
					"urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified",
					"urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
					"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
					"urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos",
					"urn:federation:authentication:windows"
				}.ToList();
		}
	}
}