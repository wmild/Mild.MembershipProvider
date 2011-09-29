using System;
using System.Collections.Specialized;
using System.Configuration.Provider;
using System.Data;
using System.Data.SqlClient;
using Mild.MembershipProvider.Helpers;

namespace Mild.MembershipProvider.Original
{
    class RoleData : Data, IRoleDataProvidable
    {
        private int CommandTimeout { get; set; }
        private string ApplicationName { get; set; }

        public void Initialize(string applicationName, SqlConnectionHolder holder, SqlRoleProvider sqlMembershipProvider, int commandTimeout)
        {
            ApplicationName = applicationName;
            Holder = holder;
            Provider = sqlMembershipProvider;
            CommandTimeout = commandTimeout;
        }

        public bool IsUserInRole(string roleName, string username)
        {
            var cmd = new SqlCommand("dbo.aspnet_UsersInRoles_IsUserInRole", Holder.Connection)
                          {
                              CommandType = CommandType.StoredProcedure,
                              CommandTimeout = CommandTimeout
                          };

            var p = new SqlParameter("@ReturnValue", SqlDbType.Int) {Direction = ParameterDirection.ReturnValue};
            cmd.Parameters.Add(p);
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@ApplicationName", SqlDbType.NVarChar,
                                                                   ApplicationName));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@UserName", SqlDbType.NVarChar, username));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@RoleName", SqlDbType.NVarChar, roleName));
            cmd.ExecuteNonQuery();
            int iStatus = DataProviderHelper.GetReturnValue(cmd);

            switch (iStatus)
            {
                case 0:
                    return false;
                case 1:
                    return true;
                case 2:
                    return false;
                    // throw new ProviderException(SR.GetString(SR.Provider_user_not_found));
                case 3:
                    return false; // throw new ProviderException(SR.GetString(SR.Provider_role_not_found, roleName));
            }
            throw new ProviderException(StringResources.GetString(StringResources.ProviderUnknownFailure));
        }

        public string[] GetRolesForUser(string username)
        {
            var cmd = new SqlCommand("dbo.aspnet_UsersInRoles_GetRolesForUser", Holder.Connection);
            var p = new SqlParameter("@ReturnValue", SqlDbType.Int);
            SqlDataReader reader = null;
            var sc = new StringCollection();

            cmd.CommandType = CommandType.StoredProcedure;
            cmd.CommandTimeout = CommandTimeout;

            p.Direction = ParameterDirection.ReturnValue;
            cmd.Parameters.Add(p);
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@ApplicationName", SqlDbType.NVarChar,
                                                                   ApplicationName));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@UserName", SqlDbType.NVarChar, username));
            try
            {
                reader = cmd.ExecuteReader(CommandBehavior.SequentialAccess);
                while (reader.Read())
                    sc.Add(reader.GetString(0));
            }
            finally
            {
                if (reader != null)
                    reader.Close();
            }
            if (sc.Count > 0)
            {
                var strReturn = new String[sc.Count];
                sc.CopyTo(strReturn, 0);
                return strReturn;
            }

            switch (DataProviderHelper.GetReturnValue(cmd))
            {
                case 0:
                    return new string[0];
                case 1:
                    return new string[0];
                    //throw new ProviderException(SR.GetString(SR.Provider_user_not_found));
                default:
                    throw new ProviderException(StringResources.GetString(StringResources.ProviderUnknownFailure));
            }
        }

        public void CreateRole(string roleName)
        {
            var cmd = new SqlCommand("dbo.aspnet_Roles_CreateRole", Holder.Connection)
            {
                CommandType = CommandType.StoredProcedure,
                CommandTimeout = CommandTimeout
            };

            var p = new SqlParameter("@ReturnValue", SqlDbType.Int) {Direction = ParameterDirection.ReturnValue};

            cmd.Parameters.Add(p);
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@ApplicationName", SqlDbType.NVarChar,
                                                                   ApplicationName));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@RoleName", SqlDbType.NVarChar, roleName));
            cmd.ExecuteNonQuery();

            int returnValue = DataProviderHelper.GetReturnValue(cmd);

            switch (returnValue)
            {
                case 0:
                    return;

                case 1:
                    throw new ProviderException(StringResources.GetString(StringResources.ProviderRoleAlreadyExists,
                                                                          roleName));

                default:
                    throw new ProviderException(StringResources.GetString(StringResources.ProviderUnknownFailure));
            }
        }

        public bool DeleteRole(string roleName, bool throwOnPopulatedRole)
        {
            var cmd = new SqlCommand("dbo.aspnet_Roles_DeleteRole", Holder.Connection)
            {
                CommandType = CommandType.StoredProcedure,
                CommandTimeout = CommandTimeout
            };

            var p = new SqlParameter("@ReturnValue", SqlDbType.Int) { Direction = ParameterDirection.ReturnValue };
            cmd.Parameters.Add(p);
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@RoleName", SqlDbType.NVarChar, roleName));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@DeleteOnlyIfRoleIsEmpty", SqlDbType.Bit, throwOnPopulatedRole ? 1 : 0));
            cmd.ExecuteNonQuery();
            int returnValue = DataProviderHelper.GetReturnValue(cmd);

            if (returnValue == 2)
            {
                throw new ProviderException(StringResources.GetString(StringResources.RoleIsNotEmpty));
            }

            return (returnValue == 0);
        }

        public bool RoleExists(string roleName)
        {
            var cmd = new SqlCommand("dbo.aspnet_Roles_RoleExists", Holder.Connection)
            {
                CommandType = CommandType.StoredProcedure,
                CommandTimeout = CommandTimeout
            };

            var p = new SqlParameter("@ReturnValue", SqlDbType.Int) { Direction = ParameterDirection.ReturnValue };
            cmd.Parameters.Add(p);
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@RoleName", SqlDbType.NVarChar, roleName));
            cmd.ExecuteNonQuery();
            int returnValue = DataProviderHelper.GetReturnValue(cmd);

            switch (returnValue)
            {
                case 0:
                    return false;
                case 1:
                    return true;
            }
            throw new ProviderException(StringResources.GetString(StringResources.ProviderUnknownFailure));
        }

        public void AddUsersToRoles(string[] roleNames, string[] usernames)
        {
            var beginTranCalled = false;
            try
            {
                int numUsersRemaing = usernames.Length;
                while (numUsersRemaing > 0)
                {
                    int iter;
                    string allUsers = usernames[usernames.Length - numUsersRemaing];
                    numUsersRemaing--;
                    for (iter = usernames.Length - numUsersRemaing; iter < usernames.Length; iter++)
                    {
                        if (allUsers.Length + usernames[iter].Length + 1 >= 4000)
                            break;
                        allUsers += "," + usernames[iter];
                        numUsersRemaing--;
                    }

                    int numRolesRemaining = roleNames.Length;
                    while (numRolesRemaining > 0)
                    {
                        string allRoles = roleNames[roleNames.Length - numRolesRemaining];
                        numRolesRemaining--;
                        for (iter = roleNames.Length - numRolesRemaining; iter < roleNames.Length; iter++)
                        {
                            if (allRoles.Length + roleNames[iter].Length + 1 >= 4000)
                                break;
                            allRoles += "," + roleNames[iter];
                            numRolesRemaining--;
                        }
                        //
                        // Note:  ADO.NET 2.0 introduced the TransactionScope class - in your own code you should use TransactionScope
                        //            rather than explicitly managing transactions with the TSQL BEGIN/COMMIT/ROLLBACK statements.
                        //
                        if (!beginTranCalled && (numUsersRemaing > 0 || numRolesRemaining > 0)) {
                            (new SqlCommand("BEGIN TRANSACTION", Holder.Connection)).ExecuteNonQuery();
                            beginTranCalled = true;
                        }
                        AddUsersToRolesCore(Holder.Connection, allUsers, allRoles);
                    }
                }
                if (beginTranCalled) {
                    (new SqlCommand("COMMIT TRANSACTION", Holder.Connection)).ExecuteNonQuery();
                    beginTranCalled = false;
                }
            } catch  {
                if (beginTranCalled) {
                    try {
                        (new SqlCommand("ROLLBACK TRANSACTION", Holder.Connection)).ExecuteNonQuery();
                    } catch {
                    }
                    beginTranCalled = false;
                }
                throw;
            } 
        }

        private void AddUsersToRolesCore(SqlConnection conn, string usernames, string roleNames)
        {
            var cmd = new SqlCommand("dbo.aspnet_UsersInRoles_AddUsersToRoles", conn);
            SqlDataReader reader = null;
            var p = new SqlParameter("@ReturnValue", SqlDbType.Int);
            string s1 = String.Empty, s2 = String.Empty;

            cmd.CommandType = CommandType.StoredProcedure;
            cmd.CommandTimeout = CommandTimeout;

            p.Direction = ParameterDirection.ReturnValue;
            cmd.Parameters.Add(p);
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@RoleNames", SqlDbType.NVarChar, roleNames));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@UserNames", SqlDbType.NVarChar, usernames));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@CurrentTimeUtc", SqlDbType.DateTime, DateTime.UtcNow));
            try
            {
                reader = cmd.ExecuteReader(CommandBehavior.SingleRow);
                if (reader.Read())
                {
                    if (reader.FieldCount > 0)
                        s1 = reader.GetString(0);
                    if (reader.FieldCount > 1)
                        s2 = reader.GetString(1);
                }
            }
            finally
            {
                if (reader != null)
                    reader.Close();
            }
            switch (DataProviderHelper.GetReturnValue(cmd))
            {
                case 0:
                    return;
                case 1:
                    throw new ProviderException(StringResources.GetString(StringResources.ProviderThisUserNotFound, s1));
                case 2:
                    throw new ProviderException(StringResources.GetString(StringResources.ProviderRoleNotFound, s1));
                case 3:
                    throw new ProviderException(StringResources.GetString(StringResources.ProviderThisUserAlreadyInRole, s1, s2));
            }
            throw new ProviderException(StringResources.GetString(StringResources.ProviderUnknownFailure));
        }

        public void RemoveUsersFromRoles(string[] roleNames, string[] usernames)
        {
            bool beginTranCalled = false;
            try
            {
                int numUsersRemaing = usernames.Length;
                while (numUsersRemaing > 0)
                {
                    int iter;
                    string allUsers = usernames[usernames.Length - numUsersRemaing];
                    numUsersRemaing--;
                    for (iter = usernames.Length - numUsersRemaing; iter < usernames.Length; iter++)
                    {
                        if (allUsers.Length + usernames[iter].Length + 1 >= 4000)
                            break;
                        allUsers += "," + usernames[iter];
                        numUsersRemaing--;
                    }

                    int numRolesRemaining = roleNames.Length;
                    while (numRolesRemaining > 0)
                    {
                        string allRoles = roleNames[roleNames.Length - numRolesRemaining];
                        numRolesRemaining--;
                        for (iter = roleNames.Length - numRolesRemaining; iter < roleNames.Length; iter++)
                        {
                            if (allRoles.Length + roleNames[iter].Length + 1 >= 4000)
                                break;
                            allRoles += "," + roleNames[iter];
                            numRolesRemaining--;
                        }
                        //
                        // Note:  ADO.NET 2.0 introduced the TransactionScope class - in your own code you should use TransactionScope
                        //            rather than explicitly managing transactions with the TSQL BEGIN/COMMIT/ROLLBACK statements.
                        //
                        if (!beginTranCalled && (numUsersRemaing > 0 || numRolesRemaining > 0))
                        {
                            (new SqlCommand("BEGIN TRANSACTION", Holder.Connection)).ExecuteNonQuery();
                            beginTranCalled = true;
                        }
                        RemoveUsersFromRolesCore(Holder.Connection, allUsers, allRoles);
                    }
                }
                if (beginTranCalled)
                {
                    (new SqlCommand("COMMIT TRANSACTION", Holder.Connection)).ExecuteNonQuery();
                    beginTranCalled = false;
                }
            }
            catch
            {
                if (beginTranCalled)
                {
                    (new SqlCommand("ROLLBACK TRANSACTION", Holder.Connection)).ExecuteNonQuery();
                    beginTranCalled = false;
                }
                throw;
            }
        }

        private void RemoveUsersFromRolesCore(SqlConnection conn, string usernames, string roleNames)
        {
            var cmd = new SqlCommand("dbo.aspnet_UsersInRoles_RemoveUsersFromRoles", conn);
            SqlDataReader reader = null;
            var p = new SqlParameter("@ReturnValue", SqlDbType.Int);
            string s1 = String.Empty, s2 = String.Empty;

            cmd.CommandType = CommandType.StoredProcedure;
            cmd.CommandTimeout = CommandTimeout;

            p.Direction = ParameterDirection.ReturnValue;
            cmd.Parameters.Add(p);
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@UserNames", SqlDbType.NVarChar, usernames));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@RoleNames", SqlDbType.NVarChar, roleNames));
            try
            {
                reader = cmd.ExecuteReader(CommandBehavior.SingleRow);
                if (reader.Read())
                {
                    if (reader.FieldCount > 0)
                        s1 = reader.GetString(0);
                    if (reader.FieldCount > 1)
                        s2 = reader.GetString(1);
                }
            }
            finally
            {
                if (reader != null)
                    reader.Close();
            }
            switch (DataProviderHelper.GetReturnValue(cmd))
            {
                case 0:
                    return;
                case 1:
                    throw new ProviderException(StringResources.GetString(StringResources.ProviderThisUserNotFound, s1));
                case 2:
                    throw new ProviderException(StringResources.GetString(StringResources.ProviderRoleNotFound, s2));
                case 3:
                    throw new ProviderException(StringResources.GetString(StringResources.ProviderThisUserAlreadyNotInRole, s1, s2));
            }
            throw new ProviderException(StringResources.GetString(StringResources.ProviderUnknownFailure));
        }

        public string[] GetUsersInRole(string roleName)
        {
            var cmd = new SqlCommand("dbo.aspnet_UsersInRoles_GetUsersInRoles", Holder.Connection);
            SqlDataReader reader = null;
            var p = new SqlParameter("@ReturnValue", SqlDbType.Int);
            var sc = new StringCollection();

            cmd.CommandType = CommandType.StoredProcedure;
            cmd.CommandTimeout = CommandTimeout;

            p.Direction = ParameterDirection.ReturnValue;
            cmd.Parameters.Add(p);
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@ApplicationName", SqlDbType.NVarChar,
                                                                   ApplicationName));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@RoleName", SqlDbType.NVarChar, roleName));
            try
            {
                reader = cmd.ExecuteReader(CommandBehavior.SequentialAccess);
                while (reader.Read())
                    sc.Add(reader.GetString(0));
            }
            finally
            {
                if (reader != null)
                    reader.Close();
            }
            if (sc.Count < 1)
            {
                switch (DataProviderHelper.GetReturnValue(cmd))
                {
                    case 0:
                        return new string[0];
                    case 1:
                        throw new ProviderException(StringResources.GetString(StringResources.ProviderRoleNotFound,
                                                                              roleName));
                }
                throw new ProviderException(StringResources.GetString(StringResources.ProviderUnknownFailure));
            }

            var strReturn = new String[sc.Count];
            sc.CopyTo(strReturn, 0);
            return strReturn;
        }

        public string[] GetAllRoles()
        {
            var cmd = new SqlCommand("dbo.aspnet_Roles_GetAllRoles", Holder.Connection);
            var sc = new StringCollection();
            var p = new SqlParameter("@ReturnValue", SqlDbType.Int);
            SqlDataReader reader = null;

            cmd.CommandType = CommandType.StoredProcedure;
            cmd.CommandTimeout = CommandTimeout;

            p.Direction = ParameterDirection.ReturnValue;
            cmd.Parameters.Add(p);
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@ApplicationName", SqlDbType.NVarChar,
                                                                   ApplicationName));
            try
            {
                reader = cmd.ExecuteReader(CommandBehavior.SequentialAccess);
                while (reader.Read())
                    sc.Add(reader.GetString(0));
            }
            finally
            {
                if (reader != null)
                    reader.Close();
            }

            var strReturn = new String[sc.Count];
            sc.CopyTo(strReturn, 0);
            return strReturn;
        }

        public string[] FindUsersInRole(string roleName, string usernameToMatch)
        {
            var cmd = new SqlCommand("dbo.aspnet_UsersInRoles_FindUsersInRole", Holder.Connection);
            SqlDataReader reader = null;
            var p = new SqlParameter("@ReturnValue", SqlDbType.Int);
            var sc = new StringCollection();

            cmd.CommandType = CommandType.StoredProcedure;
            cmd.CommandTimeout = CommandTimeout;

            p.Direction = ParameterDirection.ReturnValue;
            cmd.Parameters.Add(p);
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@ApplicationName", SqlDbType.NVarChar,
                                                                   ApplicationName));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@RoleName", SqlDbType.NVarChar, roleName));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@UserNameToMatch", SqlDbType.NVarChar,
                                                                   usernameToMatch));
            try
            {
                reader = cmd.ExecuteReader(CommandBehavior.SequentialAccess);
                while (reader.Read())
                    sc.Add(reader.GetString(0));
            }
            finally
            {
                if (reader != null)
                    reader.Close();
            }
            if (sc.Count < 1)
            {
                switch (DataProviderHelper.GetReturnValue(cmd))
                {
                    case 0:
                        return new string[0];

                    case 1:
                        throw new ProviderException(StringResources.GetString(StringResources.ProviderRoleNotFound,
                                                                              roleName));

                    default:
                        throw new ProviderException(StringResources.GetString(StringResources.ProviderUnknownFailure));
                }
            }
            var strReturn = new String[sc.Count];
            sc.CopyTo(strReturn, 0);
            return strReturn;
        }
    }
}
