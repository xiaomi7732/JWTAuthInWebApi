using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace JWT
{
    [ApiController]
    public class TokenController : ControllerBase
    {
        // 1. Not best practice to hardcode any secrets in the code.
        // 2. DRY violation: duplicate to the value in Startup.cs
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

            // Package: System.IdentityModel.Tokens.Jwt
            JwtSecurityToken token = new JwtSecurityToken(
                issuer: "saar",
                audience: "saar-audience",
                claims: new[] {
                    new Claim(JwtRegisteredClaimNames.Sub, login.UserName),
                    new Claim("whatever-I-want-to-put-here", "whatevervalue"),
                    new Claim("age","18"),
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
        /// <remarks>
        /// This is simplified. You probably need to compare the user credential with records in DB to determine if the user is valid or not.
        /// </remarks>
        private bool IsValid(UserContract login)
            => string.Equals(login?.UserName, "saar", StringComparison.OrdinalIgnoreCase) && string.Equals(login?.Password, "123", StringComparison.Ordinal);
    }
}