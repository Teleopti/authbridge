using System.ComponentModel;
using System.Runtime.Serialization;

namespace AuthBridge.Clients
{
	[DataContract]
	[EditorBrowsable(EditorBrowsableState.Never)]
	public class SalesforceClientUserData
	{
		[DataMember(Name = "first_name")]
		public string FirstName { get; set; }

		[DataMember(Name = "id")]
		public string Id { get; set; }

		[DataMember(Name = "last_name")]
		public string LastName { get; set; }

		[DataMember(Name = "username")]
		public string Username { get; set; }

		// do we need "language", "locale" from salesforce? or use the one in our system?
	}
}