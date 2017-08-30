//-----------------------------------------------------------------------
// <copyright file="MachineKeyUtil.cs" company="Microsoft">
//     Copyright (c) Microsoft. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace DotNetOpenAuth.AspNet {
	using System.Web.Security;

	/// <summary>
	/// Provides helpers that mimic the ASP.NET 4.5 MachineKey.Protect / Unprotect APIs,
	/// even when running on ASP.NET 4.0. Consumers are expected to follow the same
	/// conventions used by the MachineKey.Protect / Unprotect APIs (consult MSDN docs
	/// for how these are meant to be used). Additionally, since this helper class
	/// dynamically switches between the two based on whether the current application is
	/// .NET 4.0 or 4.5, consumers should never persist output from the Protect method
	/// since the implementation will change when upgrading 4.0 -> 4.5. This should be
	/// used for transient data only.
	/// </summary>
	internal static class MachineKeyUtil {
		/// <summary>
		/// Protects the specified user data.
		/// </summary>
		/// <param name="userData">The user data.</param>
		/// <param name="purposes">The purposes.</param>
		/// <returns>The encrypted data</returns>
		public static byte[] Protect(byte[] userData, params string[] purposes) {
			return MachineKey.Protect(userData, purposes);
		}

		/// <summary>
		/// Unprotects the specified protected data.
		/// </summary>
		/// <param name="protectedData">The protected data.</param>
		/// <param name="purposes">The purposes.</param>
		/// <returns>The unencrypted data</returns>
		public static byte[] Unprotect(byte[] protectedData, params string[] purposes) {
			return MachineKey.Unprotect(protectedData, purposes);
		}
	}
}
