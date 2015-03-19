﻿namespace AuthBridge.Web.Services
{
    public interface IFederationContext
    {
        string Realm { get; set; }

        string OriginalUrl { get; set; }

        string IssuerName { get; set; }

        string Context { get; set; }

        string GetValue(string key);

        void SetValue(string key, string value);

        void Destroy();
    }
}