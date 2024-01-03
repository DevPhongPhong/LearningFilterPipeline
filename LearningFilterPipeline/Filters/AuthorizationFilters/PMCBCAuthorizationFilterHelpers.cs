using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace LearningFilterPipeline.Filters.AuthorizationFilters;

public static class PMCBCAuthorizationFilterHelpers
{
    private static readonly JwtSecurityTokenHandler TokenHandler = new();
    /// <summary>
    /// Gen token with payload data, key, and algorithm encrypt
    /// </summary>
    /// <param name="payload">Data in token</param>
    /// <param name="key">SecretKey</param>
    /// <param name="algorithm">Name of algorithm encrypt that is an prop of Microsoft.IdentityModel.Tokens.SecurityAlgorithms</param>
    /// <returns>Token</returns>
    /// <alert>payload don't be encrypted when gen token, so u should encrypt them first</alert>
    public static string GenerateToken(string payload, string key, string algorithm = SecurityAlgorithms.HmacSha256)
    {
        var claims = new[]
        {
            new Claim("data", payload)
        };

        var credentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.ASCII.GetBytes(key)), algorithm);

        var token = new JwtSecurityToken(
            issuer: "PMCBC", // Bên gửi
            // audience: audience, // Bên nhận
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(30), // Thời gian hết hạn của token
            signingCredentials: credentials
        );

        var tokenString = TokenHandler.WriteToken(token);
        return tokenString;
    }
    /// <summary>
    /// Validate token
    /// </summary>
    /// <param name="token"></param>
    /// <param name="secret"></param>
    /// <returns></returns>
    public static bool ValidateToken(string token, string secret)
    {
        try
        {
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secret)),
                ValidateIssuer = true,
                ValidIssuer = "PMCBC", // Bên gửi
                ValidateAudience = false, // false vì gen token không truyền vào audience
                // Thêm logic xác thực audience nếu cần thiết
            };

            TokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);

            return true;
        }
        catch
        {
            return false;
        }
    }

    public static IServiceCollection AddPMCBCAuthorizationFilter(this IServiceCollection services)
    {
        services.AddSingleton<PMCBCAuthorizationFilter>();
        return services;
    }
}