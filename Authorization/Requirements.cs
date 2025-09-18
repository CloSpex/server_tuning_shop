using Microsoft.AspNetCore.Authorization;

namespace TuningStore.Authorization.Requirements
{
    public class ResourceOwnerRequirement : IAuthorizationRequirement
    {
        public ResourceOwnerRequirement() { }
    }

    public class ResourceOwnerHandler : AuthorizationHandler<ResourceOwnerRequirement>
    {
        private readonly IHttpContextAccessor _httpContextAccessor;

        public ResourceOwnerHandler(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }

        protected override Task HandleRequirementAsync(
            AuthorizationHandlerContext context,
            ResourceOwnerRequirement requirement)
        {
            var httpContext = _httpContextAccessor.HttpContext;
            if (httpContext == null)
            {
                context.Fail();
                return Task.CompletedTask;
            }

            var userIdClaim = context.User.FindFirst("sub") ?? context.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier);
            var userRole = context.User.FindFirst(System.Security.Claims.ClaimTypes.Role)?.Value;

            if (userRole == "Admin")
            {
                context.Succeed(requirement);
                return Task.CompletedTask;
            }

            if (httpContext.Request.RouteValues.TryGetValue("id", out var routeId) &&
                userIdClaim != null &&
                routeId?.ToString() == userIdClaim.Value)
            {
                context.Succeed(requirement);
                return Task.CompletedTask;
            }

            context.Fail();
            return Task.CompletedTask;
        }
    }
}