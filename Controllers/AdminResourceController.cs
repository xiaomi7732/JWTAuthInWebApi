using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JWT
{
    public class AdminResourceController : ControllerBase
    {
        private const string AllowedRoles = "Admin";
        [Route("adminResource")]
        [HttpGet]
        [Authorize(Roles = AllowedRoles)]
        public IActionResult Get()
        {
            return Ok($"This resource is granted to the role of {AllowedRoles}");
        }
    }
}