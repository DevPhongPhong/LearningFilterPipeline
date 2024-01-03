using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace LearningFilterPipeline.Filters.AuthorizationFilters;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public class PMCBCAuthorizationFilter : Attribute, IAuthorizationFilter
{
    private readonly string AuthHeader;
    private readonly string SecretKey;

    /// <summary>
    /// Constructor use DI to access appsetting.json, structure is 
    /// {
    ///     "AuthConfig": {
    ///         "SecretKey": is Secret key,
    ///         "AuthHeader": is Header name that contains auth token
    ///     }
    /// }
    /// </summary>
    /// <param name="configuration"></param>
    public PMCBCAuthorizationFilter(IConfiguration configuration)
    {
#if DEBUG
        // check AddSingleton works by Writeline Random Guid
        Console.WriteLine(Guid.NewGuid());
#endif
        string secretKey = configuration.GetValue<string>("PMCBCAuthorizationConfig:SecretKey");
        string authHeader = configuration.GetValue<string>("PMCBCAuthorizationConfig:AuthHeader");
        SecretKey = !string.IsNullOrEmpty(secretKey) ? secretKey : throw new Exception("No Secret key in appsettings.json");
        AuthHeader = !string.IsNullOrEmpty(authHeader) ? authHeader : "Authorization";
    }

    public void OnAuthorization(AuthorizationFilterContext context)
    {
        bool isAllowAnonymous = context.ActionDescriptor.EndpointMetadata.Any(obj => obj is AllowAnonymousAttribute);

        if (isAllowAnonymous) return;

        string token = context.HttpContext.Request.Headers[AuthHeader].ToString();

        if (!PMCBCAuthorizationFilterHelpers.ValidateToken(token, SecretKey))
        {
            context.Result = new StatusCodeResult(403);
            return;
        }
    }
}
