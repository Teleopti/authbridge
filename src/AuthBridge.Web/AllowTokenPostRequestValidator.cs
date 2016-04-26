using System;
using System.IdentityModel.Services;
using System.Web;
using System.Web.Util;

namespace AuthBridge.Web
{
    public class AllowTokenPostRequestValidator : RequestValidator
    {
        protected override bool IsValidRequestString(HttpContext context, string value,
                                                     RequestValidationSource requestValidationSource,
                                                     string collectionKey, out int validationFailureIndex)
        {
            validationFailureIndex = 0;
            if (requestValidationSource == RequestValidationSource.Form &&
                collectionKey.Equals(WSFederationConstants.Parameters.Result, StringComparison.Ordinal))
            {
                var message = WSFederationMessage.CreateFromFormPost(new HttpRequestWrapper(context.Request)) as SignInResponseMessage;

                if (message != null)
                {
                    return true;
                }
            }
            return base.IsValidRequestString(context, value, requestValidationSource, collectionKey,
                                             out validationFailureIndex);
        }
    }
}