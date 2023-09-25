using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace AuthBridge.Protocols.Saml
{
    public class Saml20EncryptedAssertion
    {
        private const bool UseOaepDefault = false;
        private XmlDocument _encryptedAssertion;
        private SymmetricAlgorithm _sessionKey;
        private string _sessionKeyAlgorithm = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";

        public Saml20EncryptedAssertion()
        {
        }

        public Saml20EncryptedAssertion(RSA transportKey)
            : this()
        {
            this.TransportKey = transportKey;
        }

        public Saml20EncryptedAssertion(RSA transportKey, XmlDocument encryptedAssertion)
            : this(transportKey)
        {
            this.LoadXml(encryptedAssertion.DocumentElement);
        }

        public XmlDocument Assertion { get; set; }

        public string SessionKeyAlgorithm
        {
            get => this._sessionKeyAlgorithm;
            set => this._sessionKeyAlgorithm = value.StartsWith("http://www.w3.org/2001/04/xmlenc#") ? value : throw new ArgumentException("The session key algorithm must be specified using the identifying URIs listed in the specification.");
        }

        public RSA TransportKey { get; set; }

        private SymmetricAlgorithm SessionKey
        {
            get
            {
                if (this._sessionKey == null)
                {
                    this._sessionKey = Saml20EncryptedAssertion.GetKeyInstance(this._sessionKeyAlgorithm);
                    this._sessionKey.GenerateKey();
                }
                return this._sessionKey;
            }
        }

        public void Decrypt()
        {
            if (this.TransportKey == null)
                throw new InvalidOperationException("The \"TransportKey\" property must contain the asymmetric key to decrypt the assertion.");
            XmlElement xmlElement = this._encryptedAssertion != null ? Saml20EncryptedAssertion.GetElement("EncryptedData", "http://www.w3.org/2001/04/xmlenc#", this._encryptedAssertion.DocumentElement) : throw new InvalidOperationException("Unable to find the <EncryptedAssertion> element. Use a constructor or the LoadXml - method to set it.");
            System.Security.Cryptography.Xml.EncryptedData encryptedData = new System.Security.Cryptography.Xml.EncryptedData();
            encryptedData.LoadXml(xmlElement);
            SymmetricAlgorithm sessionKey;
            if (encryptedData.EncryptionMethod != null)
            {
                this._sessionKeyAlgorithm = encryptedData.EncryptionMethod.KeyAlgorithm;
                sessionKey = this.ExtractSessionKey(this._encryptedAssertion, this._sessionKeyAlgorithm);
            }
            else
                sessionKey = this.ExtractSessionKey(this._encryptedAssertion);
            byte[] bytes = new EncryptedXml().DecryptData(encryptedData, sessionKey);
            this.Assertion = new XmlDocument()
            {
                PreserveWhitespace = true
            };
            try
            {
                this.Assertion.Load((TextReader) new StringReader(Encoding.UTF8.GetString(bytes)));
            }
            catch (XmlException ex)
            {
                this.Assertion = (XmlDocument) null;
                throw new InvalidOperationException("Unable to parse the decrypted assertion.", (Exception) ex);
            }
        }

        // public void Encrypt()
        // {
        //     if (this.TransportKey == null)
        //         throw new InvalidOperationException("The \"TransportKey\" property is required to encrypt the assertion.");
        //     if (this.Assertion == null)
        //         throw new InvalidOperationException("The \"Assertion\" property is required for this operation.");
        //     System.Security.Cryptography.Xml.EncryptedData encryptedData1 = new System.Security.Cryptography.Xml.EncryptedData();
        //     encryptedData1.Type = "http://www.w3.org/2001/04/xmlenc#Element";
        //     encryptedData1.EncryptionMethod = new System.Security.Cryptography.Xml.EncryptionMethod(this._sessionKeyAlgorithm);
        //     System.Security.Cryptography.Xml.EncryptedData encryptedData2 = encryptedData1;
        //     byte[] numArray = new EncryptedXml().EncryptData(this.Assertion.DocumentElement, this.SessionKey, false);
        //     encryptedData2.CipherData.CipherValue = numArray;
        //     encryptedData2.KeyInfo = new KeyInfo();
        //     System.Security.Cryptography.Xml.EncryptedKey encryptedKey1 = new System.Security.Cryptography.Xml.EncryptedKey();
        //     encryptedKey1.EncryptionMethod = new System.Security.Cryptography.Xml.EncryptionMethod("http://www.w3.org/2001/04/xmlenc#rsa-1_5");
        //     encryptedKey1.CipherData = new System.Security.Cryptography.Xml.CipherData(EncryptedXml.EncryptKey(this.SessionKey.Key, this.TransportKey, false));
        //     System.Security.Cryptography.Xml.EncryptedKey encryptedKey2 = encryptedKey1;
        //     encryptedData2.KeyInfo.AddClause((KeyInfoClause) new KeyInfoEncryptedKey(encryptedKey2));
        //     EncryptedAssertion encryptedAssertion1 = new EncryptedAssertion();
        //     encryptedAssertion1.EncryptedData = new SAML2.Schema.XEnc.EncryptedData();
        //     EncryptedAssertion encryptedAssertion2 = encryptedAssertion1;
        //     XmlDocument xmlDocument = new XmlDocument();
        //     xmlDocument.LoadXml(Serialization.SerializeToXmlString<EncryptedAssertion>(encryptedAssertion2));
        //     EncryptedXml.ReplaceElement(Saml20EncryptedAssertion.GetElement("EncryptedData", "http://www.w3.org/2001/04/xmlenc#", xmlDocument.DocumentElement), encryptedData2, false);
        //     this._encryptedAssertion = xmlDocument;
        // }

        public XmlDocument GetXml() => this._encryptedAssertion;

        public void LoadXml(XmlElement element)
        {
            Saml20EncryptedAssertion.CheckEncryptedAssertionElement(element);
            this._encryptedAssertion = new XmlDocument();
            this._encryptedAssertion.AppendChild(this._encryptedAssertion.ImportNode((XmlNode) element, true));
        }

        public void WriteAssertion(XmlWriter writer) => this._encryptedAssertion.WriteTo(writer);

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
            XmlNodeList elementsByTagName = doc.GetElementsByTagName(element, elementNS);
            return elementsByTagName.Count != 0 ? (XmlElement) elementsByTagName[0] : (XmlElement) null;
        }

        private static SymmetricAlgorithm GetKeyInstance(string algorithm)
        {
            SymmetricAlgorithm keyInstance;
            switch (algorithm)
            {
                case "http://www.w3.org/2001/04/xmlenc#tripledes-cbc":
                    keyInstance = (SymmetricAlgorithm) TripleDES.Create();
                    break;
                case "http://www.w3.org/2001/04/xmlenc#aes128-cbc":
                    RijndaelManaged rijndaelManaged1 = new RijndaelManaged();
                    rijndaelManaged1.KeySize = 128;
                    keyInstance = (SymmetricAlgorithm) rijndaelManaged1;
                    break;
                case "http://www.w3.org/2001/04/xmlenc#aes192-cbc":
                    RijndaelManaged rijndaelManaged2 = new RijndaelManaged();
                    rijndaelManaged2.KeySize = 192;
                    keyInstance = (SymmetricAlgorithm) rijndaelManaged2;
                    break;
                default:
                    RijndaelManaged rijndaelManaged3 = new RijndaelManaged();
                    rijndaelManaged3.KeySize = 256;
                    keyInstance = (SymmetricAlgorithm) rijndaelManaged3;
                    break;
            }
            return keyInstance;
        }

        private SymmetricAlgorithm ExtractSessionKey(XmlDocument encryptedAssertionDoc) => this.ExtractSessionKey(encryptedAssertionDoc, string.Empty);

        private SymmetricAlgorithm ExtractSessionKey(
            XmlDocument encryptedAssertionDoc,
            string keyAlgorithm)
        {
            foreach (XmlNode childNode in encryptedAssertionDoc.DocumentElement.ChildNodes)
            {
                if (childNode.LocalName == "EncryptedKey" && childNode.NamespaceURI == "http://www.w3.org/2001/04/xmlenc#")
                    return this.ToSymmetricKey((XmlElement) childNode, keyAlgorithm);
            }
            XmlElement encryptedKeyElement = Saml20EncryptedAssertion.GetElement("EncryptedData", "http://www.w3.org/2001/04/xmlenc#", encryptedAssertionDoc.DocumentElement) != null ? Saml20EncryptedAssertion.GetElement("EncryptedKey", "http://www.w3.org/2001/04/xmlenc#", encryptedAssertionDoc.DocumentElement) : throw new InvalidOperationException("Unable to locate assertion decryption key.");
            if (encryptedKeyElement != null)
                return this.ToSymmetricKey(encryptedKeyElement, keyAlgorithm);
            throw new InvalidOperationException("Unable to get assertion decryption key.");
        }

        private SymmetricAlgorithm ToSymmetricKey(XmlElement encryptedKeyElement, string keyAlgorithm)
        {
            System.Security.Cryptography.Xml.EncryptedKey encryptedKey = new System.Security.Cryptography.Xml.EncryptedKey();
            encryptedKey.LoadXml(encryptedKeyElement);
            bool useOAEP = false;
            if (encryptedKey.EncryptionMethod != null)
                useOAEP = encryptedKey.EncryptionMethod.KeyAlgorithm == "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
            if (encryptedKey.CipherData.CipherValue == null)
                throw new NotImplementedException("Unable to decode CipherData of type \"CipherReference\".");
            SymmetricAlgorithm keyInstance = Saml20EncryptedAssertion.GetKeyInstance(keyAlgorithm);
            keyInstance.Key = EncryptedXml.DecryptKey(encryptedKey.CipherData.CipherValue, this.TransportKey, useOAEP);
            return keyInstance;
        }
    }
}