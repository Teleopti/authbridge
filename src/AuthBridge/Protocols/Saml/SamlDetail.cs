using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Web;
using System.Xml;
using Microsoft.IdentityModel.Tokens;

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

	public class AuthRequest
	{
		public string Id;
		private readonly string _issueInstant;
		private readonly string _assertionConsumerServiceUrl;
		private readonly string _issuer;
		private readonly string _audienceRestriction;

		[Flags]
		public enum AuthRequestFormat
		{
			Base64 = 1,
			Compressed = 2,
			UrlEncode = 4,
		}

		public AuthRequest(string assertionConsumerServiceUrl, string issuer, string audienceRestriction)
		{
			_assertionConsumerServiceUrl = assertionConsumerServiceUrl;
			_issuer = issuer;
			_audienceRestriction = audienceRestriction;
			Id = "_" + Guid.NewGuid();
			_issueInstant = DateTime.Now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ");
		}

		public string GetRequest(AuthRequestFormat format)
		{
			const string protocol = "urn:oasis:names:tc:SAML:2.0:protocol";
			const string assertion = "urn:oasis:names:tc:SAML:2.0:assertion";
			using (var sw = new StringWriter())
			{
				var xws = new XmlWriterSettings {OmitXmlDeclaration = true};
				using (var xw = XmlWriter.Create(sw, xws))
				{
					xw.WriteStartElement("samlp", "AuthnRequest", protocol);
					xw.WriteAttributeString("ID", Id);
					xw.WriteAttributeString("Version", "2.0");
					xw.WriteAttributeString("IssueInstant", _issueInstant);
					xw.WriteAttributeString("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
					xw.WriteAttributeString("AssertionConsumerServiceURL", _assertionConsumerServiceUrl);

					xw.WriteStartElement("saml", "Issuer", assertion);
					xw.WriteString(_issuer);
					xw.WriteEndElement();

					xw.WriteStartElement("samlp", "NameIDPolicy", protocol);
					xw.WriteAttributeString("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
					xw.WriteAttributeString("AllowCreate", "true");
					xw.WriteEndElement();

					if (!string.IsNullOrEmpty(_audienceRestriction))
					{
						xw.WriteStartElement("saml", "Conditions", assertion);
						xw.WriteStartElement("saml", "AudienceRestriction", assertion);
						xw.WriteStartElement("saml", "Audience", assertion);
						xw.WriteString(_audienceRestriction);
						xw.WriteEndElement();
						xw.WriteEndElement();
						xw.WriteEndElement();
					}

					xw.WriteStartElement("samlp", "RequestedAuthnContext", protocol);
					xw.WriteAttributeString("Comparison", "minimum");

					xw.WriteStartElement("saml", "AuthnContextClassRef", assertion);
					xw.WriteString("urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified");
					xw.WriteEndElement();
					xw.WriteStartElement("saml", "AuthnContextClassRef", assertion);
					xw.WriteString("urn:oasis:names:tc:SAML:2.0:ac:classes:Password");
					xw.WriteEndElement();
					xw.WriteStartElement("saml", "AuthnContextClassRef", assertion);
					xw.WriteString("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
					xw.WriteEndElement();
					xw.WriteStartElement("saml", "AuthnContextClassRef", assertion);
					xw.WriteString("urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos");
					xw.WriteEndElement();
					xw.WriteStartElement("saml", "AuthnContextClassRef", assertion);
					xw.WriteString("urn:federation:authentication:windows");
					xw.WriteEndElement();

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
	}
}