using System;
using System.Collections.Concurrent;
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
        // Key: userName; Guid: refresh token value.
        // Recommend to persistent this alone with the user records.
        // Based on the scenario, you might have 1 user, 1 refresh token or 1 user, multiple refresh tokens.
        static readonly ConcurrentDictionary<string, Guid> _refreshToken = new ConcurrentDictionary<string, Guid>();

        // 1. Not best practice to hardcode any secrets in the code.
        // 2. DRY violation: duplicate to the value in Startup.cs
        private const string Secret = "this is my custom Secret key for authentication";

        // Returns an JWT token when the login info is valid.
        [Route("token")]
        [HttpPost()]
        public IActionResult GetToken([FromBody] UserContract login)
        {
            AuthenticationResult authenticationResult = GetAuthenticationResult(login);

            if (authenticationResult is null)
            {
                return Forbid();
            }

            return Ok(authenticationResult);
        }

        [Route("refresh")]
        [HttpPost()]
        public IActionResult RefreshToken([FromBody] AuthenticationResult oldResult)
        {
            if (!IsValid(oldResult, out string validUserName))
            {
                return Forbid();
            }
            return Ok(CreateAuthResult(validUserName));
        }

        [Route("revoke/{userName}")]
        [HttpPost]
        public IActionResult RevokeRefreshToken(string userName)
        {
            if (_refreshToken.TryRemove(userName, out _))
            {
                return NoContent();
            }
            return BadRequest("User doesn't exist");
        }

        /// <summary>
        /// Returns an access token when the login is valid. Returns null otherwise;
        /// </summary>
        private AuthenticationResult GetAuthenticationResult(UserContract login)
        {
            if (!IsValid(login))
            {
                return null;
            }

            return CreateAuthResult(login.UserName);
        }

        private AuthenticationResult CreateAuthResult(string userName)
        {
            // Package: System.IdentityModel.Tokens.Jwt
            DateTime expiry = DateTime.UtcNow.AddSeconds(30);
            JwtSecurityToken token = new JwtSecurityToken(
                issuer: "saar",
                audience: "saar-audience",
                claims: new[] {
                    new Claim(JwtRegisteredClaimNames.Sub, userName),
                    new Claim("whatever-I-want-to-put-here", "whatevervalue"),
                    new Claim(ClaimTypes.Role, "Admin") // Usually getting roles from database for the current user
                },
                expires: expiry,
                signingCredentials: new SigningCredentials(
                    key: new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Secret)),
                    algorithm: SecurityAlgorithms.HmacSha256
                )
            );
            return new AuthenticationResult
            {
                AccessToken = (new JwtSecurityTokenHandler()).WriteToken(token),
                RefreshToken = GenerateRefreshToken(userName),
                Expiry = expiry,
            };
        }

        /// <summary>
        /// Verify if the user matches the record.
        /// </summary>
        /// <remarks>
        /// This is simplified. You probably need to compare the user credential with records in DB to determine if the user is valid or not.
        /// </remarks>
        private bool IsValid(UserContract login)
            => string.Equals(login?.UserName, "saar", StringComparison.OrdinalIgnoreCase) && string.Equals(login?.Password, "123", StringComparison.Ordinal);

        private bool IsValid(AuthenticationResult authResult, out string validUserName)
        {
            validUserName = string.Empty;

            ClaimsPrincipal principal = GetPrincipalFromExpiredToken(authResult.AccessToken);
            if (principal is null)
            {
                return false;
            }

            validUserName = principal.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(validUserName))
            {
                return false;
            }

            if (!Guid.TryParse(authResult.RefreshToken, out Guid givenRefreshToken))
            {
                return false;
            }

            if (!_refreshToken.TryGetValue(validUserName, out Guid currentRefreshToken))
            {
                return false;
            }

            if (currentRefreshToken != givenRefreshToken)
            {
                return false;
            }

            return true;
        }

        private ClaimsPrincipal GetPrincipalFromExpiredToken(string accessToken)
        {
            TokenValidationParameters tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Secret)),
                ValidateLifetime = false,
            };

            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            ClaimsPrincipal principal = tokenHandler.ValidateToken(accessToken, tokenValidationParameters, out SecurityToken securityToken);
            if (securityToken is not JwtSecurityToken jwtSecurityToken || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("Invalid token");
            }

            return principal;
        }

        private string GenerateRefreshToken(string userName)
        {
            Guid newRefreshToken = _refreshToken.AddOrUpdate(userName, (u) => Guid.NewGuid(), (k, old) => Guid.NewGuid());
            return newRefreshToken.ToString("D");
        }
    }
}