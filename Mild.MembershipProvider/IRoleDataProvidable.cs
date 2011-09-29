namespace Mild.MembershipProvider
{
    public interface IRoleDataProvidable : IDataProvidable
    {
        void Initialize(string applicationName, SqlConnectionHolder holder,
                                SqlRoleProvider sqlMembershipProvider, int commandTimeout);

        bool IsUserInRole(string roleName, string username);
        string[] GetRolesForUser(string username);
        void CreateRole(string roleName);
        bool DeleteRole(string roleName, bool throwOnPopulatedRole);
        bool RoleExists(string roleName);
        void AddUsersToRoles(string[] roleNames, string[] usernames);
        void RemoveUsersFromRoles(string[] roleNames, string[] usernames);
        string[] GetUsersInRole(string roleName);
        string[] GetAllRoles();
        string[] FindUsersInRole(string roleName, string usernameToMatch);
    }
}
