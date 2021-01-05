using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace JWT
{
    [ApiController]
    public class TokenController : ControllerBase
    {
        private const string Secret = "this is my custom Secret key for authentication";

        // Returns an JWT token when the login info is valid.
        [Route("token")]
        [HttpPost()]
        public IActionResult GetToken([FromBody] UserContract login)
        {
            string accessToken = GetAccessToken(login);

            if (string.IsNullOrEmpty(accessToken))
            {
                return Forbid();
            }

            return Ok(new
            {
                token = accessToken,
            });
        }

        /// <summary>
        /// Returns an access token when the login is valid. Returns null otherwise;
        /// </summary>
        private string GetAccessToken(UserContract login)
        {
            if (!IsValid(login))
            {
                return null;
            }

            JwtSecurityToken token = new JwtSecurityToken(
                issuer: "saar", "saar-audience",
                claims: new[]{
                    new Claim(JwtRegisteredClaimNames.Sub, login.UserName),
                    new Claim("whatever-I-want-to-put-here", "whatevervalue"),
                },
                expires: DateTime.UtcNow.AddMinutes(5),
                signingCredentials: new SigningCredentials(
                    key: new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Secret)),
                    algorithm: SecurityAlgorithms.HmacSha256
                )
             );

            return (new JwtSecurityTokenHandler()).WriteToken(token);
        }

        /// <summary>
        /// Verify if the user matches the record.
        /// </summary>
        /// <param name="login"></param>
        /// <returns></returns>
        private bool IsValid(UserContract login)
            => string.Equals(login?.UserName, "saar", StringComparison.OrdinalIgnoreCase) && string.Equals(login?.Password, "123", StringComparison.Ordinal);
    }
}