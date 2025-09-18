namespace TuningStore.Authorization.Policies
{
    public static class AuthorizationPolicies
    {
        public const string AdminOnly = "AdminOnly";
        public const string ResourceOwner = "ResourceOwner";
        public const string UserOrAdmin = "UserOrAdmin";
    }
}