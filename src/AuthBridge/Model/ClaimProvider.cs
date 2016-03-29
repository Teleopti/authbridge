﻿namespace AuthBridge.Model
{
    using System;
    using System.Collections.Specialized;

    public class ClaimProvider
    {
        public Uri Identifier { get; set; }

		public string DisplayName { get; set; }

        public Uri Url { get; set; }

        public string Protocol { get; set; }

		public bool IdpInitiated { get; set; }

        public string Profile { get; set; }

        public NameValueCollection Parameters { get; set; }
    }
}
