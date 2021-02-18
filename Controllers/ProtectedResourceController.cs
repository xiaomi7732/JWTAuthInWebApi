using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JWT
{
    public class ProtectedResourceController : ControllerBase
    {
        [Route("protectedInfo")]
        [HttpGet]
        [Authorize(Roles = "User")]
        public IActionResult Get()
        {
            return Ok("You can see this message means you are a valid user.");
        }
    }
}