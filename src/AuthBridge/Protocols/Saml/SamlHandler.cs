using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.IdentityModel.Metadata;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.ServiceModel.Security;
using System.Text;
using System.Web;
using System.Xml;
using AuthBridge.Model;
using AuthBridge.Utilities;
using log4net;
using ClaimTypes = System.IdentityModel.Claims.ClaimTypes;

namespace AuthBridge.Protocols.Saml
{
	public class SamlHandler : ProtocolHandlerBase
	{
		private string[] _signingKeyThumbprint;
		private readonly string _issuer;
        private readonly string _replyUrl;
		private string _identityProviderSSOURL;
		private readonly string _audienceRestriction;
		public bool WantAuthnRequestsSigned { get; private set; }
		private bool _usePost;
		private readonly string _requestedAuthnContextComparisonMethod;
		private readonly List<string> _authnContextClassRefs;
		private readonly bool _noRequestedAuthnContext;
		private static readonly ILog Logger = LogManager.GetLogger(typeof(SamlHandler));
        
        public SamlHandler(ClaimProvider issuer) : base(issuer)
		{
			_issuer = string.IsNullOrEmpty(issuer.Parameters["issuer"]) ? MultiProtocolIssuer.Identifier.ToString() : issuer.Parameters["issuer"];
			_replyUrl = string.IsNullOrEmpty(issuer.Parameters["replyUrl"]) ? MultiProtocolIssuer.ReplyUrl.ToString() : issuer.Parameters["replyUrl"];
			if (!string.IsNullOrEmpty(issuer.Parameters["metadataUrl"]))
			{
				ParseMetadata(issuer);
			}
			else
			{
				_signingKeyThumbprint = new[] {issuer.Parameters["signingKeyThumbprint"].ToLowerInvariant()};
				_identityProviderSSOURL = issuer.Parameters["identityProviderSSOURL"];
                WantAuthnRequestsSigned = (issuer.Parameters["wantAuthnRequestsSigned"] == "true");
                _usePost = (issuer.Parameters["usePost"] == "true");
			}
			_audienceRestriction = issuer.Parameters["audienceRestriction"];
			_requestedAuthnContextComparisonMethod = issuer.Parameters["requestedAuthnContextComparisonMethod"];
			var authnContextClassRefs = issuer.Parameters["authnContextClassRefs"];
			_authnContextClassRefs = !string.IsNullOrWhiteSpace(authnContextClassRefs) ? authnContextClassRefs.Split(',').ToList() : new List<string>();
			_noRequestedAuthnContext = issuer.Parameters["noRequestedAuthnContext"] == "true";
		}


		private void ParseMetadata(ClaimProvider issuer)
		{
			ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12;
			var serializer = new MetadataSerializer {CertificateValidationMode = X509CertificateValidationMode.None};
			if ("true".Equals(issuer.Parameters["ignoreSslError"], StringComparison.InvariantCultureIgnoreCase))
			{
				ServicePointManager.ServerCertificateValidationCallback += (s, ce, ch, ssl) => true;
			}
			var metadata = serializer.ReadMetadata(XmlReader.Create(issuer.Parameters["metadataUrl"]));
			var entityDescriptor = (EntityDescriptor) metadata;
			
			var idpsso = entityDescriptor.RoleDescriptors.OfType<IdentityProviderSingleSignOnDescriptor>().First();
            WantAuthnRequestsSigned = idpsso.WantAuthenticationRequestsSigned;

            if (idpsso == null)
			{
				throw new InvalidOperationException("Missing IdentityProviderSingleSignOnDescriptor!");
			}
			Logger.Info("Got IdentityProviderSingleSignOnDescriptor from metadata.");
			var postEndpoint = idpsso.SingleSignOnServices.SingleOrDefault(x => x.Binding.ToString() == Saml2Constants.PostBinding);
			if (postEndpoint != null)
			{
				_usePost = true;
				_identityProviderSSOURL = postEndpoint.Location.ToString();
			}
			else
			{
				_usePost = false;
				_identityProviderSSOURL = idpsso.SingleSignOnServices.Single(x => x.Binding.ToString() == Saml2Constants.RedirectBinding).Location.ToString();
			}
			Logger.Info($"usePost: {_usePost}, identityProviderSSOURL: {_identityProviderSSOURL}");
			_signingKeyThumbprint = GetSigningKeyThumbprint(idpsso).ToArray();
			if(Logger.IsInfoEnabled)
				Logger.Info($"signing key thumbprints: {string.Join(", ", _signingKeyThumbprint)}");
		}

		private static IEnumerable<string> GetSigningKeyThumbprint(RoleDescriptor ssod)
		{
			var x509DataClauses = ssod.Keys.Where(key => key.KeyInfo != null && key.Use == KeyType.Signing)
				.Select(key => key.KeyInfo.OfType<X509RawDataKeyIdentifierClause>().First());
			var tokens = new List<X509SecurityToken>();
			tokens.AddRange(x509DataClauses.Select(token => new X509SecurityToken(new X509Certificate2(token.GetX509RawData()))));
			Logger.Info($"Get signing keys: {tokens.Count}");
			return tokens.Select(x => x.Certificate.Thumbprint.ToLowerInvariant());
		}
		
		private static void RedirectWithData(NameValueCollection data, string url)
		{
			var response = HttpContext.Current.Response;
			response.Clear();

			var s = new StringBuilder();
			s.Append("<html>");
			s.AppendFormat("<body onload='document.forms[\"form\"].submit()'>");
			s.AppendFormat("<form name='form' action='{0}' method='post'>", url);
			foreach (string key in data)
			{
				s.AppendFormat("<input type='hidden' name='{0}' value='{1}' />", key, data[key]);
			}
			s.Append("</form></body></html>");
			response.Write(s.ToString());
			response.End();
		}

		public override void ProcessSignInRequest(Scope scope, HttpContextBase httpContext)
		{
			var samlRequest = new AuthRequest(_replyUrl, _issuer, _audienceRestriction, _requestedAuthnContextComparisonMethod, _authnContextClassRefs, _identityProviderSSOURL);
			var returnUrl = GetReturnUrlQueryParameterFromUrl(httpContext.Request.UrlConsideringLoadBalancerHeaders().AbsoluteUri);

			if (_usePost)
			{
				var preparedRequest = samlRequest.GetRequest(AuthRequest.AuthRequestFormat.Base64, WantAuthnRequestsSigned? MultiProtocolIssuer.SigningCertificate : null, _noRequestedAuthnContext);
				var nameValueCollection = new NameValueCollection
				{
					{"SAMLRequest", preparedRequest}, {"RelayState", returnUrl}
				};
				RedirectWithData(nameValueCollection, _identityProviderSSOURL);
			}
			else
			{
				var preparedRequest = samlRequest.GetRequest(AuthRequest.AuthRequestFormat.Base64 | AuthRequest.AuthRequestFormat.Compressed | AuthRequest.AuthRequestFormat.UrlEncode, WantAuthnRequestsSigned? MultiProtocolIssuer.SigningCertificate : null, _noRequestedAuthnContext);
				var redirectUrl = _identityProviderSSOURL.Contains("?")
					? $"{_identityProviderSSOURL}&SAMLRequest={preparedRequest}&RelayState={returnUrl}"
					: $"{_identityProviderSSOURL}?SAMLRequest={preparedRequest}&RelayState={returnUrl}";
				try
				{
					httpContext.Response.Redirect(redirectUrl);
					httpContext.Response.End();
				}
				catch (Exception ex) when (HttpContext.Current.Response.HeadersWritten)
				{
					Logger.Error("exception while redirect to provider", ex);
				}
			}
		}
		
		public override ClaimsIdentity ProcessSignInResponse(string realm, string originalUrl, HttpContextBase httpContext)
		{
			Logger.Info("ProcessSignInResponse");
			var s = httpContext.Request.Form["SAMLResponse"];
			var information = GetSamlDetail(s);

			Logger.InfoFormat("information.Issuer: {0}, information.SubjectNameId: {1}", information.Issuer, information.SubjectNameId);
			//You must add a claims policy for the protocol identifier!
			var issuerIdentifier = information.Issuer;
			var claims = new List<Claim>
			{
				new Claim(ClaimTypes.NameIdentifier, information.SubjectNameId)
			};
			return new ClaimsIdentity(claims, issuerIdentifier);
		}

		public SamlDetail GetSamlDetail(string s)
		{
			var response = Encoding.UTF8.GetString(Convert.FromBase64String(s));
			Logger.InfoFormat("SAMLResponse: {0}", response);
			var doc = new XmlDocument { PreserveWhitespace = true };
			doc.LoadXml(response);
			VerifySignatures(doc);
			Logger.Info("Verified signature successfully");

			if (!VerifyStatus(doc))
			{
				ThrowAndLogWarn("The SAML response status was not 'status:Success'");
			}

			Logger.Info("Verified status successfully");

			SamlDetail information;
			var elementsByTagName1 = doc.GetElementsByTagName("EncryptedAssertion", "urn:oasis:names:tc:SAML:2.0:assertion");
			if (elementsByTagName1.Count == 1)
			{
				var encryptedAssertionXml = new XmlDocument { PreserveWhitespace = true };
				var copiedNode =
					encryptedAssertionXml.ImportNode(doc.SelectSingleNode("//*[local-name() = 'EncryptedAssertion']"), true);
				encryptedAssertionXml.AppendChild(copiedNode);
				var encryptedAssertion =
					new Saml20EncryptedAssertion((RSA)MultiProtocolIssuer.SigningCertificate.PrivateKey,
						encryptedAssertionXml);
				encryptedAssertion.Decrypt();
				var decryptedDocument = encryptedAssertion.Assertion;
				information = ExtractInformation(decryptedDocument);
			}
			else
			{
				information = ExtractInformation(doc);
			}

			Logger.InfoFormat("Extracted information: SubjectNameId: {0}, Issuer: {1}, NotBefore: {2}, NotOnOrAfter: {3}",
				information.SubjectNameId, information.Issuer, information.NotBefore, information.NotOnOrAfter);

			if (!VerifyAudience(information))
			{
				ThrowAndLog("Audience does not match the white list values.");
			}

			Logger.Info("Verified audience successfully");

			if (!VerifyAllowedDateTimeRange(information))
			{
				ThrowAndLogWarn("This SAML response is not valid any longer.");
			}

			Logger.Info("Verified allowed date time range successfully");
			return information;
		}

		private static void ThrowAndLogWarn(string message)
		{
			Logger.Warn(message);
			throw new InvalidOperationException(message);
		}

		private static void ThrowAndLog(string message)
		{
			Logger.Error(message);
			throw new InvalidOperationException(message);
		}

		private static string GetReturnUrlQueryParameterFromUrl(string context)
		{
			var queryNameValueCollection = HttpUtility.ParseQueryString(context);

			var returnUrl = queryNameValueCollection["wctx"];
			if (!string.IsNullOrEmpty(returnUrl))
			{
				returnUrl = returnUrl.Replace("ru=", "");
				if (!returnUrl.Contains("WsFedOwinState") && !returnUrl.EndsWith("/"))
					returnUrl += "/";
			}
			return returnUrl;
		}

		private static bool VerifyAllowedDateTimeRange(SamlDetail detail)
		{
			var utcnow = DateTime.UtcNow.TruncateToSecond();
			var notBefore = detail.NotBefore.TruncateToSecond();
			var notOnOrAfter = detail.NotOnOrAfter.TruncateToSecond();
			var notBeforeSubtract5Second = notBefore.Subtract(TimeSpan.FromSeconds(5));
			Logger.InfoFormat($"utcnow: {utcnow}, notBefore: {notBefore}, notOnOrAfter: {notOnOrAfter}, notBeforeSubtract5Second <= utcnow: {notBeforeSubtract5Second <= utcnow}, utcnow < notOnOrAfter: {utcnow < notOnOrAfter}");
			return notBeforeSubtract5Second <= utcnow && utcnow < notOnOrAfter;
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
			if (nameIdElement == null)
			{
				ThrowAndLog("NameID Claim Policy not configured correctly.");
			}
			detail.SubjectNameId = nameIdElement.InnerText;

			var issuerElement = doc.SelectSingleNode("//*[local-name()='Issuer']");
			detail.Issuer = issuerElement.InnerText;
			var audienceElements = doc.SelectNodes("//*[local-name()='Conditions']/*[local-name()='AudienceRestriction']/*[local-name()='Audience']");
			detail.AudienceRestrictions = new List<string>();
			if (audienceElements != null)
			{
				foreach (var audienceElement in audienceElements)
					detail.AudienceRestrictions.Add(((XmlNode)audienceElement).InnerText);
			}
			return detail;
		}

		private void VerifySignatures(XmlDocument xmlDoc)
		{
			var isThumbprintCorrect = false;
			foreach (XmlElement item in xmlDoc.SelectNodes("//*[local-name()='Signature']"))
			{
				var node = item;
				if (node.ParentNode != xmlDoc.DocumentElement)
				{
					var doc = new XmlDocument();
					var parentNode = doc.ImportNode(item.ParentNode, true);
					doc.AppendChild(parentNode);
					node = (XmlElement)parentNode.SelectSingleNode("*[local-name()='Signature']");
				}

				var signedXml = new SignedXml((XmlElement)node.ParentNode);
				signedXml.LoadXml(node);
				CheckSignature(signedXml, node);
				var x509Data = signedXml.Signature.KeyInfo.OfType<KeyInfoX509Data>().First();
				var cert = x509Data.Certificates.OfType<X509Certificate2>().First();
				if (cert.Thumbprint != null && Array.IndexOf(_signingKeyThumbprint, cert.Thumbprint.ToLowerInvariant()) > -1)
				{
					isThumbprintCorrect = true;
				}
			}

			if (!isThumbprintCorrect)
			{
				ThrowAndLog("The thumbprint doesn't match the white list values.");
			}
		}

		public static void CheckSignature(SignedXml signedXml, XmlElement node)
		{
			if ((ConfigurationManager.AppSettings["checkSignature"] ?? "false").Trim().ToLower() == "true")
			{
				if (!signedXml.CheckSignature())
				{
					ThrowAndLogWarn($"Verify {node.ParentNode.Name} signature failed.");
				}
			}
		}

		private static bool VerifyStatus(XmlDocument doc)
		{
			var statusCode = doc.SelectSingleNode("//*[local-name()='Status']/*[local-name()='StatusCode']");
			return statusCode.Attributes["Value"].Value.EndsWith("status:Success");
		}

		private bool VerifyAudience(SamlDetail information)
		{
			if (string.IsNullOrEmpty(_audienceRestriction))
				return true;

			return information.AudienceRestrictions.Contains(_audienceRestriction);
		}
	}
}