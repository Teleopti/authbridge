using System;
using System.Configuration;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace AuthBridge.Protocols.Saml
{
    public class Saml20EncryptedAssertion
    {
        private XmlDocument _encryptedAssertion;
        private string _sessionKeyAlgorithm = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";

        public Saml20EncryptedAssertion()
        {
        }

        public Saml20EncryptedAssertion(RSA transportKey)
            : this()
        {
            TransportKey = transportKey;
        }

        public Saml20EncryptedAssertion(RSA transportKey, XmlDocument encryptedAssertion)
            : this(transportKey)
        {
            LoadXml(encryptedAssertion.DocumentElement);
        }

        public XmlDocument Assertion { get; set; }

        public RSA TransportKey { get; }

        public void Decrypt()
        {
            if (TransportKey == null)
                throw new InvalidOperationException("The \"TransportKey\" property must contain the asymmetric key to decrypt the assertion.");
            var xmlElement = _encryptedAssertion != null ? GetElement("EncryptedData", "http://www.w3.org/2001/04/xmlenc#", this._encryptedAssertion.DocumentElement) : throw new InvalidOperationException("Unable to find the <EncryptedAssertion> element. Use a constructor or the LoadXml - method to set it.");
            var encryptedData = new EncryptedData();
            encryptedData.LoadXml(xmlElement);
            SymmetricAlgorithm sessionKey;
            if (encryptedData.EncryptionMethod != null)
            {
                _sessionKeyAlgorithm = encryptedData.EncryptionMethod.KeyAlgorithm;
                sessionKey = ExtractSessionKey(_encryptedAssertion, _sessionKeyAlgorithm);
            }
            else
                sessionKey = ExtractSessionKey(_encryptedAssertion);
            var bytes = new EncryptedXml().DecryptData(encryptedData, sessionKey);
            Assertion = new XmlDocument()
            {
                PreserveWhitespace = true
            };
            try
            {
                Assertion.Load(new StringReader(Encoding.UTF8.GetString(bytes)));
            }
            catch (XmlException ex)
            {
                Assertion = null;
                throw new InvalidOperationException("Unable to parse the decrypted assertion.", ex);
            }
        }

        public void LoadXml(XmlElement element)
        {
            CheckEncryptedAssertionElement(element);
            _encryptedAssertion = new XmlDocument();
            _encryptedAssertion.AppendChild(_encryptedAssertion.ImportNode((XmlNode) element, true));
        }

        private static void CheckEncryptedAssertionElement(XmlElement element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof (element));
            if (element.LocalName != "EncryptedAssertion")
                throw new ArgumentException("The element must be of type \"EncryptedAssertion\".");
            if (element.NamespaceURI != "urn:oasis:names:tc:SAML:2.0:assertion")
                throw new ArgumentException("The element must be of type \"urn:oasis:names:tc:SAML:2.0:assertion#EncryptedAssertion\".");
        }

        private static XmlElement GetElement(string element, string elementNS, XmlElement doc)
        {
            var elementsByTagName = doc.GetElementsByTagName(element, elementNS);
            return elementsByTagName.Count != 0 ? (XmlElement) elementsByTagName[0] : null;
        }

        private static SymmetricAlgorithm GetKeyInstance(string algorithm)
        {
            SymmetricAlgorithm keyInstance;
            switch (algorithm)
            {
                case "http://www.w3.org/2001/04/xmlenc#tripledes-cbc":
                    keyInstance = TripleDES.Create();
                    break;
                case "http://www.w3.org/2001/04/xmlenc#aes128-cbc":
                    var rijndaelManaged1 = new RijndaelManaged();
                    rijndaelManaged1.KeySize = 128;
                    keyInstance = rijndaelManaged1;
                    break;
                case "http://www.w3.org/2001/04/xmlenc#aes192-cbc":
                    var rijndaelManaged2 = new RijndaelManaged();
                    rijndaelManaged2.KeySize = 192;
                    keyInstance = rijndaelManaged2;
                    break;
                default:
                    var algorithmName = ConfigurationManager.AppSettings["SymmetricAlgorithm"];
                    if (!string.IsNullOrWhiteSpace(algorithmName))
                    {
                        keyInstance = SymmetricAlgorithm.Create(algorithmName);
                    }
                    else
                    {
                        var rijndaelManaged3 = new RijndaelManaged();
                        rijndaelManaged3.KeySize = 256;
                        keyInstance = rijndaelManaged3;
                    }
                    break;
            }
            return keyInstance;
        }

        private SymmetricAlgorithm ExtractSessionKey(XmlDocument encryptedAssertionDoc) => ExtractSessionKey(encryptedAssertionDoc, string.Empty);

        private SymmetricAlgorithm ExtractSessionKey(
            XmlDocument encryptedAssertionDoc,
            string keyAlgorithm)
        {
            foreach (XmlNode childNode in encryptedAssertionDoc.DocumentElement.ChildNodes)
            {
                if (childNode.LocalName == "EncryptedKey" && childNode.NamespaceURI == "http://www.w3.org/2001/04/xmlenc#")
                    return ToSymmetricKey((XmlElement) childNode, keyAlgorithm);
            }
            var encryptedKeyElement = GetElement("EncryptedData", "http://www.w3.org/2001/04/xmlenc#", encryptedAssertionDoc.DocumentElement) != null ? Saml20EncryptedAssertion.GetElement("EncryptedKey", "http://www.w3.org/2001/04/xmlenc#", encryptedAssertionDoc.DocumentElement) : throw new InvalidOperationException("Unable to locate assertion decryption key.");
            if (encryptedKeyElement != null)
                return ToSymmetricKey(encryptedKeyElement, keyAlgorithm);
            throw new InvalidOperationException("Unable to get assertion decryption key.");
        }

        private SymmetricAlgorithm ToSymmetricKey(XmlElement encryptedKeyElement, string keyAlgorithm)
        {
            var encryptedKey = new EncryptedKey();
            encryptedKey.LoadXml(encryptedKeyElement);
            var useOAEP = false;
            if (encryptedKey.EncryptionMethod != null)
                useOAEP = encryptedKey.EncryptionMethod.KeyAlgorithm == "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
            if (encryptedKey.CipherData.CipherValue == null)
                throw new NotImplementedException("Unable to decode CipherData of type \"CipherReference\".");
            SymmetricAlgorithm keyInstance = GetKeyInstance(keyAlgorithm);
            keyInstance.Key = EncryptedXml.DecryptKey(encryptedKey.CipherData.CipherValue, TransportKey, useOAEP);
            return keyInstance;
        }
    }
}