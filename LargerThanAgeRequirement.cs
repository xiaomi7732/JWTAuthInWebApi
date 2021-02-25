using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;

namespace JWT
{
    public class LargerThanAgeRequirement : IAuthorizationRequirement
    {
        public LargerThanAgeRequirement(int targetAge = 18)
        {
            TargetAge = targetAge;
        }

        public int TargetAge { get; }
    }

    public class LargerThan18AuthorizationHandler : AuthorizationHandler<LargerThanAgeRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, LargerThanAgeRequirement requirement)
        {
            if(!context.User.HasClaim(claim => claim.Type == "age"))
            {
                return Task.CompletedTask;
            }

            if(!int.TryParse(context.User.FindFirst(claim => claim.Type=="age").Value, out int userAge))
            {
                return Task.CompletedTask;
            }

            if(userAge > requirement.TargetAge)
            {
                context.Succeed(requirement);
            }
            return Task.CompletedTask;
        }
    }
}