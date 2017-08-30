//-----------------------------------------------------------------------
// <copyright file="CryptoKeyCollisionException.cs" company="Outercurve Foundation">
//     Copyright (c) Outercurve Foundation. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace DotNetOpenAuth.Messaging.Bindings {
	using System;
	using System.Diagnostics.CodeAnalysis;
	using System.Security.Permissions;

	/// <summary>
	/// Thrown by a hosting application or web site when a cryptographic key is created with a
	/// bucket and handle that conflicts with a previously stored and unexpired key.
	/// </summary>
	[SuppressMessage("Microsoft.Design", "CA1032:ImplementStandardExceptionConstructors", Justification = "Specialized exception has no need of a message parameter.")]
	[Serializable]
	public class CryptoKeyCollisionException : ArgumentException {
		/// <summary>
		/// Initializes a new instance of the <see cref="CryptoKeyCollisionException"/> class.
		/// </summary>
		public CryptoKeyCollisionException() {
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="CryptoKeyCollisionException"/> class.
		/// </summary>
		/// <param name="inner">The inner exception to include.</param>
		public CryptoKeyCollisionException(Exception inner) : base(null, inner) {
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="CryptoKeyCollisionException"/> class.
		/// </summary>
		/// <param name="info">The <see cref="System.Runtime.Serialization.SerializationInfo"/> 
		/// that holds the serialized object data about the exception being thrown.</param>
		/// <param name="context">The System.Runtime.Serialization.StreamingContext 
		/// that contains contextual information about the source or destination.</param>
		protected CryptoKeyCollisionException(
		  System.Runtime.Serialization.SerializationInfo info,
		  System.Runtime.Serialization.StreamingContext context)
			: base(info, context) {
			throw new NotImplementedException();
		}
	}
}
