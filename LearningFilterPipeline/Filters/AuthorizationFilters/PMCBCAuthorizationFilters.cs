using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace LearningFilterPipeline.Filters.AuthorizationFilters
{
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
    public class PMCBCAuthorizationFilters : Attribute, IAuthorizationFilter
    {
        public string Secret = "PMCBC_Secret";

        public bool ValidateToken(string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(Secret);

                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    // check có đúng chữ ký số đã phát không
                    ValidateIssuerSigningKey = true,
                    // chữ ký số được sử dụng là gì
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    // check người phát hành chữ ký số (chưa hiểu lắm)
                    ValidateIssuer = false,
                    // check người nhận chữ ký số (chưa hiểu lắm)
                    ValidateAudience = false,
                    // cho phép chênh lệch thời gian khi xác thực token hay không (tính thời gian xử lý xác thực)
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                return true;
            }
            catch
            {
                return false;
            }
        }

        public void OnAuthorization(AuthorizationFilterContext context)
        {
            Console.WriteLine("OnAuthorization has been call!");
        }

        public static string GenerateToken(string id, string secretKey, object payload)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(secretKey);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                new Claim("id", id)
            }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}
