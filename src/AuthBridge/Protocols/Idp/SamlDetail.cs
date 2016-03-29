using System;

namespace AuthBridge.Protocols.Idp
{
	public class SamlDetail
	{
		public string Issuer { get; set; }
		public string SubjectNameId { get; set; }
		public DateTime NotBefore { get; set; }
		public DateTime NotOnOrAfter { get; set; }
	}
}