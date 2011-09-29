using System;
using System.Configuration.Provider;
using System.Data;
using System.Data.SqlClient;
using System.Web.Security;
using Mild.MembershipProvider.Helpers;
using Mild.MembershipProvider.ViewModels;

namespace Mild.MembershipProvider.Original
{
    public class MembershipData : Data, IMembershipDataProvidable
    {
        private int CommandTimeout { get; set; }
        private string ApplicationName { get; set; }

        public void Initialize(string applicationName, SqlConnectionHolder holder, SqlMembershipProvider sqlMembershipProvider, int commandTimeout)
        {
            ApplicationName = applicationName;
            Holder = holder;
            Provider = sqlMembershipProvider;
            CommandTimeout = commandTimeout;
        }

        public CreateUserViewModel CreateUser(string salt, string pass, string encodedPasswordAnswer,
            string username, string email, string passwordQuestion, object providerUserKey,
            bool isApproved, bool requiresUniqueEmail, MembershipPasswordFormat passwordFormat)
        {
            DateTime dt = DataProviderHelper.RoundToSeconds(DateTime.UtcNow);
            var cmd = new SqlCommand("dbo.aspnet_Membership_CreateUser", Holder.Connection)
            {
                CommandTimeout = CommandTimeout,
                CommandType = CommandType.StoredProcedure
            };

            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@UserName", SqlDbType.NVarChar, username));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@Password", SqlDbType.NVarChar, pass));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@PasswordSalt", SqlDbType.NVarChar, salt));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@Email", SqlDbType.NVarChar, email));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@PasswordQuestion", SqlDbType.NVarChar, passwordQuestion));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@PasswordAnswer", SqlDbType.NVarChar, encodedPasswordAnswer));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@IsApproved", SqlDbType.Bit, isApproved));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@UniqueEmail", SqlDbType.Int, requiresUniqueEmail ? 1 : 0));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@PasswordFormat", SqlDbType.Int, (int)passwordFormat));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@CurrentTimeUtc", SqlDbType.DateTime, dt));
            SqlParameter p = DataProviderHelper.CreateInputParam("@UserId", SqlDbType.UniqueIdentifier, providerUserKey);
            p.Direction = ParameterDirection.InputOutput;
            cmd.Parameters.Add(p);

            p = new SqlParameter("@ReturnValue", SqlDbType.Int) { Direction = ParameterDirection.ReturnValue };
            cmd.Parameters.Add(p);

            cmd.ExecuteNonQuery();
            var iStatus = ((p.Value != null) ? ((int)p.Value) : -1);
            if (iStatus < 0 || iStatus > (int)MembershipCreateStatus.ProviderError)
                iStatus = (int)MembershipCreateStatus.ProviderError;
            return new CreateUserViewModel
                       {
                Status = iStatus,
                UserId = new Guid(cmd.Parameters["@UserId"].Value.ToString()),
                Date = dt
            };
        }

        public bool ChangePassword(string username, string newPasswordQuestion, string encodedPasswordAnswer)
        {
            new SchemaVersion(this, Provider, Holder.Connection).Check();

            var cmd = new SqlCommand("dbo.aspnet_Membership_ChangePasswordQuestionAndAnswer", Holder.Connection)
            {
                CommandTimeout = CommandTimeout,
                CommandType = CommandType.StoredProcedure
            };

            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@UserName", SqlDbType.NVarChar, username));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@NewPasswordQuestion", SqlDbType.NVarChar, newPasswordQuestion));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@NewPasswordAnswer", SqlDbType.NVarChar, encodedPasswordAnswer));

            var p = new SqlParameter("@ReturnValue", SqlDbType.Int) { Direction = ParameterDirection.ReturnValue };
            cmd.Parameters.Add(p);

            cmd.ExecuteNonQuery();
            var status = ((p.Value != null) ? ((int)p.Value) : -1);
            if (status != 0)
            {
                throw new ProviderException(DataProviderHelper.GetExceptionText(status));
            }

            return (status == 0);
        }

        public int ChangePassword(string username, MembershipPasswordFormat passwordFormat, string salt, string pass)
        {
            var cmd = new SqlCommand("dbo.aspnet_Membership_SetPassword", Holder.Connection)
            {
                CommandTimeout = CommandTimeout,
                CommandType = CommandType.StoredProcedure
            };

            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@UserName", SqlDbType.NVarChar, username));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@NewPassword", SqlDbType.NVarChar, pass));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@PasswordSalt", SqlDbType.NVarChar, salt));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@PasswordFormat", SqlDbType.Int, passwordFormat));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@CurrentTimeUtc", SqlDbType.DateTime, DateTime.UtcNow));

            var p = new SqlParameter("@ReturnValue", SqlDbType.Int) { Direction = ParameterDirection.ReturnValue };
            cmd.Parameters.Add(p);

            cmd.ExecuteNonQuery();

            return ((p.Value != null) ? ((int)p.Value) : -1);
        }

        public int ResetPassword(string username, MembershipPasswordFormat passwordFormat, string salt, string encodedPasswordAnswer, string newPassword,
            int maxInvalidPasswordAttempts, int passwordAttemptWindow, bool requiresQuestionAndAnswer)
        {
            var cmd = new SqlCommand("dbo.aspnet_Membership_ResetPassword", Holder.Connection)
            {
                CommandTimeout = CommandTimeout,
                CommandType = CommandType.StoredProcedure
            };

            var membershipPasswordFormat = (MembershipPasswordFormat)passwordFormat;

            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@UserName", SqlDbType.NVarChar, username));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@NewPassword", SqlDbType.NVarChar, DataProviderHelper.EncodePassword(newPassword, membershipPasswordFormat, salt)));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@MaxInvalidPasswordAttempts", SqlDbType.Int, maxInvalidPasswordAttempts));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@PasswordAttemptWindow", SqlDbType.Int, passwordAttemptWindow));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@PasswordSalt", SqlDbType.NVarChar, salt));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@PasswordFormat", SqlDbType.Int, membershipPasswordFormat));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@CurrentTimeUtc", SqlDbType.DateTime, DateTime.UtcNow));
            if (requiresQuestionAndAnswer)
            {
                cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@PasswordAnswer", SqlDbType.NVarChar, encodedPasswordAnswer));
            }

            var p = new SqlParameter("@ReturnValue", SqlDbType.Int) { Direction = ParameterDirection.ReturnValue };
            cmd.Parameters.Add(p);

            cmd.ExecuteNonQuery();

            int status = ((p.Value != null) ? ((int)p.Value) : -1);
            return status;
        }

        public int UpdateUser(MembershipUser user, bool requiresUniqueEmail)
        {
            var cmd = new SqlCommand("dbo.aspnet_Membership_UpdateUser", Holder.Connection)
            {
                CommandTimeout = CommandTimeout,
                CommandType = CommandType.StoredProcedure
            };

            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@UserName", SqlDbType.NVarChar, user.UserName));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@Email", SqlDbType.NVarChar, user.Email));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@Comment", SqlDbType.NText, user.Comment));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@IsApproved", SqlDbType.Bit, user.IsApproved ? 1 : 0));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@LastLoginDate", SqlDbType.DateTime, user.LastLoginDate.ToUniversalTime()));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@LastActivityDate", SqlDbType.DateTime, user.LastActivityDate.ToUniversalTime()));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@UniqueEmail", SqlDbType.Int, requiresUniqueEmail ? 1 : 0));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@CurrentTimeUtc", SqlDbType.DateTime, DateTime.UtcNow));

            var p = new SqlParameter("@ReturnValue", SqlDbType.Int) { Direction = ParameterDirection.ReturnValue };
            cmd.Parameters.Add(p);
            cmd.ExecuteNonQuery();
            return ((p.Value != null) ? ((int)p.Value) : -1);
        }

        public int UnlockUser(string username)
        {
            var cmd = new SqlCommand("dbo.aspnet_Membership_UnlockUser", Holder.Connection)
            {
                CommandTimeout = CommandTimeout,
                CommandType = CommandType.StoredProcedure
            };

            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@UserName", SqlDbType.NVarChar, username));

            var p = new SqlParameter("@ReturnValue", SqlDbType.Int) { Direction = ParameterDirection.ReturnValue };
            cmd.Parameters.Add(p);

            cmd.ExecuteNonQuery();

            return ((p.Value != null) ? ((int)p.Value) : -1);
        }

        public MembershipUser GetUser(object providerUserKey, bool userIsOnline, string name)
        {
            SqlDataReader reader = null;

            try
            {

                var cmd = new SqlCommand("dbo.aspnet_Membership_GetUserByUserId", Holder.Connection)
                {
                    CommandTimeout = CommandTimeout,
                    CommandType = CommandType.StoredProcedure
                };

                cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@UserId", SqlDbType.UniqueIdentifier, providerUserKey));
                cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@UpdateLastActivity", SqlDbType.Bit, userIsOnline));
                cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@CurrentTimeUtc", SqlDbType.DateTime, DateTime.UtcNow));
                var p = new SqlParameter("@ReturnValue", SqlDbType.Int) { Direction = ParameterDirection.ReturnValue };
                cmd.Parameters.Add(p);

                reader = cmd.ExecuteReader();
                if (reader.Read())
                {
                    string email = DataProviderHelper.GetNullableString(reader, 0);
                    string passwordQuestion = DataProviderHelper.GetNullableString(reader, 1);
                    string comment = DataProviderHelper.GetNullableString(reader, 2);
                    bool isApproved = reader.GetBoolean(3);
                    DateTime dtCreate = reader.GetDateTime(4).ToLocalTime();
                    DateTime dtLastLogin = reader.GetDateTime(5).ToLocalTime();
                    DateTime dtLastActivity = reader.GetDateTime(6).ToLocalTime();
                    DateTime dtLastPassChange = reader.GetDateTime(7).ToLocalTime();
                    string userName = DataProviderHelper.GetNullableString(reader, 8);
                    bool isLockedOut = reader.GetBoolean(9);
                    DateTime dtLastLockoutDate = reader.GetDateTime(10).ToLocalTime();

                    ////////////////////////////////////////////////////////////
                    // Step 4 : Return the result
                    return new MembershipUser(name,
                                               userName,
                                               providerUserKey,
                                               email,
                                               passwordQuestion,
                                               comment,
                                               isApproved,
                                               isLockedOut,
                                               dtCreate,
                                               dtLastLogin,
                                               dtLastActivity,
                                               dtLastPassChange,
                                               dtLastLockoutDate);
                }

                return null;
            }
            finally
            {
                if (reader != null)
                {
                    reader.Close();
                }
            }
        }

        public MembershipUser GetUserByName(string username, bool userIsOnline, string name)
        {
            SqlDataReader reader = null;

            try
            {

                var cmd = new SqlCommand("dbo.aspnet_Membership_GetUserByName", Holder.Connection)
                {
                    CommandTimeout = CommandTimeout,
                    CommandType = CommandType.StoredProcedure
                };

                cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
                cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@UserName", SqlDbType.NVarChar, username));
                cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@UpdateLastActivity", SqlDbType.Bit, userIsOnline));
                cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@CurrentTimeUtc", SqlDbType.DateTime, DateTime.UtcNow));
                var p = new SqlParameter("@ReturnValue", SqlDbType.Int) { Direction = ParameterDirection.ReturnValue };
                cmd.Parameters.Add(p);

                reader = cmd.ExecuteReader();
                if (reader.Read())
                {
                    string email = DataProviderHelper.GetNullableString(reader, 0);
                    string passwordQuestion = DataProviderHelper.GetNullableString(reader, 1);
                    string comment = DataProviderHelper.GetNullableString(reader, 2);
                    bool isApproved = reader.GetBoolean(3);
                    DateTime dtCreate = reader.GetDateTime(4).ToLocalTime();
                    DateTime dtLastLogin = reader.GetDateTime(5).ToLocalTime();
                    DateTime dtLastActivity = reader.GetDateTime(6).ToLocalTime();
                    DateTime dtLastPassChange = reader.GetDateTime(7).ToLocalTime();
                    Guid userId = reader.GetGuid(8);
                    bool isLockedOut = reader.GetBoolean(9);
                    DateTime dtLastLockoutDate = reader.GetDateTime(10).ToLocalTime();

                    ////////////////////////////////////////////////////////////
                    // Step 4 : Return the result
                    return new MembershipUser(name,
                                               username,
                                               userId,
                                               email,
                                               passwordQuestion,
                                               comment,
                                               isApproved,
                                               isLockedOut,
                                               dtCreate,
                                               dtLastLogin,
                                               dtLastActivity,
                                               dtLastPassChange,
                                               dtLastLockoutDate);
                }

                return null;

            }
            finally
            {
                if (reader != null)
                {
                    reader.Close();
                }
            }
        }

        public string GetUsername(string email, bool requiresUniqueEmail)
        {
            var cmd = new SqlCommand("dbo.aspnet_Membership_GetUserByEmail", Holder.Connection);
            string username = null;
            SqlDataReader reader = null;

            cmd.CommandTimeout = CommandTimeout;
            cmd.CommandType = CommandType.StoredProcedure;
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@Email", SqlDbType.NVarChar, email));

            var p = new SqlParameter("@ReturnValue", SqlDbType.Int) { Direction = ParameterDirection.ReturnValue };
            cmd.Parameters.Add(p);
            try
            {
                reader = cmd.ExecuteReader(CommandBehavior.SequentialAccess);
                if (reader.Read())
                {
                    username = DataProviderHelper.GetNullableString(reader, 0);
                    if (requiresUniqueEmail && reader.Read())
                    {
                        throw new ProviderException(StringResources.GetString(StringResources.MembershipMoreThanOneUserWithEmail));
                    }
                }
            }
            finally
            {
                if (reader != null)
                    reader.Close();
            }
            return username;
        }

        public bool DeleteUser(string username, bool deleteAllRelatedData)
        {
            var cmd = new SqlCommand("dbo.aspnet_Users_DeleteUser", Holder.Connection)
            {
                CommandTimeout = CommandTimeout,
                CommandType = CommandType.StoredProcedure
            };

            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@UserName", SqlDbType.NVarChar, username));

            cmd.Parameters.Add(deleteAllRelatedData
                                    ? DataProviderHelper.CreateInputParam("@TablesToDeleteFrom", SqlDbType.Int, 0xF)
                                    : DataProviderHelper.CreateInputParam("@TablesToDeleteFrom", SqlDbType.Int, 1));

            var p = new SqlParameter("@NumTablesDeletedFrom", SqlDbType.Int) { Direction = ParameterDirection.Output };
            cmd.Parameters.Add(p);
            cmd.ExecuteNonQuery();

            int status = ((p.Value != null) ? ((int)p.Value) : -1);

            return (status > 0);
        }

        public MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords, string name)
        {
            var users = new MembershipUserCollection();
            totalRecords = 0;

            var cmd = new SqlCommand("dbo.aspnet_Membership_GetAllUsers", Holder.Connection);
            SqlDataReader reader = null;
            var p = new SqlParameter("@ReturnValue", SqlDbType.Int);

            cmd.CommandTimeout = CommandTimeout;
            cmd.CommandType = CommandType.StoredProcedure;
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@PageIndex", SqlDbType.Int, pageIndex));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@PageSize", SqlDbType.Int, pageSize));
            p.Direction = ParameterDirection.ReturnValue;
            cmd.Parameters.Add(p);
            try
            {
                reader = cmd.ExecuteReader(CommandBehavior.SequentialAccess);
                while (reader.Read())
                {
                    string username = DataProviderHelper.GetNullableString(reader, 0);
                    string email = DataProviderHelper.GetNullableString(reader, 1);
                    string passwordQuestion = DataProviderHelper.GetNullableString(reader, 2);
                    string comment = DataProviderHelper.GetNullableString(reader, 3);
                    bool isApproved = reader.GetBoolean(4);
                    DateTime dtCreate = reader.GetDateTime(5).ToLocalTime();
                    DateTime dtLastLogin = reader.GetDateTime(6).ToLocalTime();
                    DateTime dtLastActivity = reader.GetDateTime(7).ToLocalTime();
                    DateTime dtLastPassChange = reader.GetDateTime(8).ToLocalTime();
                    Guid userId = reader.GetGuid(9);
                    bool isLockedOut = reader.GetBoolean(10);
                    DateTime dtLastLockoutDate = reader.GetDateTime(11).ToLocalTime();

                    users.Add(new MembershipUser(name,
                                                    username,
                                                    userId,
                                                    email,
                                                    passwordQuestion,
                                                    comment,
                                                    isApproved,
                                                    isLockedOut,
                                                    dtCreate,
                                                    dtLastLogin,
                                                    dtLastActivity,
                                                    dtLastPassChange,
                                                    dtLastLockoutDate));
                }
            }
            finally
            {
                if (reader != null)
                    reader.Close();
                if (p.Value != null && p.Value is int)
                    totalRecords = (int) p.Value;
            }
            return users;
        }

        public int GetNumberOfUsersOnline()
        {
            var cmd = new SqlCommand("dbo.aspnet_Membership_GetNumberOfUsersOnline", Holder.Connection);
            var p = new SqlParameter("@ReturnValue", SqlDbType.Int);

            cmd.CommandTimeout = CommandTimeout;
            cmd.CommandType = CommandType.StoredProcedure;
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@MinutesSinceLastInActive", SqlDbType.Int, Membership.UserIsOnlineTimeWindow));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@CurrentTimeUtc", SqlDbType.DateTime, DateTime.UtcNow));
            p.Direction = ParameterDirection.ReturnValue;
            cmd.Parameters.Add(p);
            cmd.ExecuteNonQuery();
            int num = ((p.Value != null) ? ((int)p.Value) : -1);
            return num;
        }

        public MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize, out int totalRecords, string name)
        {
            totalRecords = 0;
            var p = new SqlParameter("@ReturnValue", SqlDbType.Int) { Direction = ParameterDirection.ReturnValue };
            var cmd = new SqlCommand("dbo.aspnet_Membership_FindUsersByName", Holder.Connection);
            var users = new MembershipUserCollection();
            SqlDataReader reader = null;

            cmd.CommandTimeout = CommandTimeout;
            cmd.CommandType = CommandType.StoredProcedure;
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@UserNameToMatch", SqlDbType.NVarChar, usernameToMatch));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@PageIndex", SqlDbType.Int, pageIndex));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@PageSize", SqlDbType.Int, pageSize));
            cmd.Parameters.Add(p);
            try
            {
                reader = cmd.ExecuteReader(CommandBehavior.SequentialAccess);
                while (reader.Read())
                {
                    string username = DataProviderHelper.GetNullableString(reader, 0);
                    string email = DataProviderHelper.GetNullableString(reader, 1);
                    string passwordQuestion = DataProviderHelper.GetNullableString(reader, 2);
                    string comment = DataProviderHelper.GetNullableString(reader, 3);
                    bool isApproved = reader.GetBoolean(4);
                    DateTime dtCreate = reader.GetDateTime(5).ToLocalTime();
                    DateTime dtLastLogin = reader.GetDateTime(6).ToLocalTime();
                    DateTime dtLastActivity = reader.GetDateTime(7).ToLocalTime();
                    DateTime dtLastPassChange = reader.GetDateTime(8).ToLocalTime();
                    Guid userId = reader.GetGuid(9);
                    bool isLockedOut = reader.GetBoolean(10);
                    DateTime dtLastLockoutDate = reader.GetDateTime(11).ToLocalTime();

                    users.Add(new MembershipUser(name,
                                                    username,
                                                    userId,
                                                    email,
                                                    passwordQuestion,
                                                    comment,
                                                    isApproved,
                                                    isLockedOut,
                                                    dtCreate,
                                                    dtLastLogin,
                                                    dtLastActivity,
                                                    dtLastPassChange,
                                                    dtLastLockoutDate));
                }

                return users;
            }
            finally
            {
                if (reader != null)
                    reader.Close();
                if (p.Value != null && p.Value is int)
                    totalRecords = (int)p.Value;
            }
        }

        public MembershipUserCollection FindUserByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords, string name)
        {
            totalRecords = 0;
            var p = new SqlParameter("@ReturnValue", SqlDbType.Int) { Direction = ParameterDirection.ReturnValue };

            var cmd = new SqlCommand("dbo.aspnet_Membership_FindUsersByEmail", Holder.Connection);
            var users = new MembershipUserCollection();
            SqlDataReader reader = null;

            cmd.CommandTimeout = CommandTimeout;
            cmd.CommandType = CommandType.StoredProcedure;
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@ApplicationName", SqlDbType.NVarChar,
                                                                   ApplicationName));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@EmailToMatch", SqlDbType.NVarChar, emailToMatch));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@PageIndex", SqlDbType.Int, pageIndex));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@PageSize", SqlDbType.Int, pageSize));
            cmd.Parameters.Add(p);
            try
            {
                reader = cmd.ExecuteReader(CommandBehavior.SequentialAccess);
                while (reader.Read())
                {
                    string username = DataProviderHelper.GetNullableString(reader, 0);
                    string email = DataProviderHelper.GetNullableString(reader, 1);
                    string passwordQuestion = DataProviderHelper.GetNullableString(reader, 2);
                    string comment = DataProviderHelper.GetNullableString(reader, 3);
                    bool isApproved = reader.GetBoolean(4);
                    DateTime dtCreate = reader.GetDateTime(5).ToLocalTime();
                    DateTime dtLastLogin = reader.GetDateTime(6).ToLocalTime();
                    DateTime dtLastActivity = reader.GetDateTime(7).ToLocalTime();
                    DateTime dtLastPassChange = reader.GetDateTime(8).ToLocalTime();
                    Guid userId = reader.GetGuid(9);
                    bool isLockedOut = reader.GetBoolean(10);
                    DateTime dtLastLockoutDate = reader.GetDateTime(11).ToLocalTime();

                    users.Add(new MembershipUser(name,
                                                 username,
                                                 userId,
                                                 email,
                                                 passwordQuestion,
                                                 comment,
                                                 isApproved,
                                                 isLockedOut,
                                                 dtCreate,
                                                 dtLastLogin,
                                                 dtLastActivity,
                                                 dtLastPassChange,
                                                 dtLastLockoutDate));
                }

                return users;
            }
            finally
            {
                if (reader != null)
                    reader.Close();
                if (p.Value != null && p.Value is int)
                    totalRecords = (int)p.Value;
            }
        }

        public bool CheckPassword(string username, bool updateLastLoginActivityDate, bool isPasswordCorrect, DateTime lastLoginDate, DateTime lastActivityDate,
            int maxInvalidPasswordAttempts, int passwordAttemptWindow)
        {
            var cmd = new SqlCommand("dbo.aspnet_Membership_UpdateUserInfo", Holder.Connection);
            var dtNow = DateTime.UtcNow;
            cmd.CommandTimeout = CommandTimeout;
            cmd.CommandType = CommandType.StoredProcedure;
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@UserName", SqlDbType.NVarChar, username));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@IsPasswordCorrect", SqlDbType.Bit, isPasswordCorrect));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@UpdateLastLoginActivityDate", SqlDbType.Bit, updateLastLoginActivityDate));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@MaxInvalidPasswordAttempts", SqlDbType.Int, maxInvalidPasswordAttempts));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@PasswordAttemptWindow", SqlDbType.Int, passwordAttemptWindow));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@CurrentTimeUtc", SqlDbType.DateTime, dtNow));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@LastLoginDate", SqlDbType.DateTime, isPasswordCorrect ? dtNow : lastLoginDate));
            cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@LastActivityDate", SqlDbType.DateTime, isPasswordCorrect ? dtNow : lastActivityDate));
            var p = new SqlParameter("@ReturnValue", SqlDbType.Int) { Direction = ParameterDirection.ReturnValue };
            cmd.Parameters.Add(p);

            cmd.ExecuteNonQuery();

            return isPasswordCorrect;
        }

        public int GetPasswordWithFormat(string username, bool updateLastLoginActivityDate, out string password, out MembershipPasswordFormat passwordFormat, out string passwordSalt, out int failedPasswordAttemptCount, out int failedPasswordAnswerAttemptCount, out bool isApproved, out DateTime lastLoginDate, out DateTime lastActivityDate)
        {
            int status;
            SqlDataReader reader = null;
            SqlParameter p = null;

            try
            {

                var cmd = new SqlCommand("dbo.aspnet_Membership_GetPasswordWithFormat", Holder.Connection)
                {
                    CommandTimeout = CommandTimeout,
                    CommandType = CommandType.StoredProcedure
                };

                cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
                cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@UserName", SqlDbType.NVarChar, username));
                cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@UpdateLastLoginActivityDate", SqlDbType.Bit, updateLastLoginActivityDate));
                cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@CurrentTimeUtc", SqlDbType.DateTime, DateTime.UtcNow));

                p = new SqlParameter("@ReturnValue", SqlDbType.Int) { Direction = ParameterDirection.ReturnValue };
                cmd.Parameters.Add(p);

                reader = cmd.ExecuteReader(CommandBehavior.SingleRow);

                status = -1;

                if (reader.Read())
                {
                    password = reader.GetString(0);
                    passwordFormat = (MembershipPasswordFormat)reader.GetInt32(1);
                    passwordSalt = reader.GetString(2);
                    failedPasswordAttemptCount = reader.GetInt32(3);
                    failedPasswordAnswerAttemptCount = reader.GetInt32(4);
                    isApproved = reader.GetBoolean(5);
                    lastLoginDate = reader.GetDateTime(6);
                    lastActivityDate = reader.GetDateTime(7);
                }
                else
                {
                    password = null;
                    passwordFormat = 0;
                    passwordSalt = null;
                    failedPasswordAttemptCount = 0;
                    failedPasswordAnswerAttemptCount = 0;
                    isApproved = false;
                    lastLoginDate = DateTime.UtcNow;
                    lastActivityDate = DateTime.UtcNow;
                }
            }
            finally
            {
                if (reader != null)
                {
                    reader.Close();

                    status = ((p.Value != null) ? ((int)p.Value) : -1);
                }
            }
            return status;
        }

        public string GetPasswordFromDB(string username, bool requiresQuestionAndAnswer, string passwordAnswer, out int status, out MembershipPasswordFormat passwordFormat, int maxInvalidPasswordAttempts, int passwordAttemptWindow)
        {
            SqlDataReader reader = null;
            SqlParameter p = null;

            try
            {
                var cmd = new SqlCommand("dbo.aspnet_Membership_GetPassword", Holder.Connection)
                {
                    CommandTimeout = CommandTimeout,
                    CommandType = CommandType.StoredProcedure
                };

                cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
                cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@UserName", SqlDbType.NVarChar, username));
                cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@MaxInvalidPasswordAttempts", SqlDbType.Int, maxInvalidPasswordAttempts));
                cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@PasswordAttemptWindow", SqlDbType.Int, passwordAttemptWindow));
                cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@CurrentTimeUtc", SqlDbType.DateTime, DateTime.UtcNow));

                if (requiresQuestionAndAnswer)
                {
                    cmd.Parameters.Add(DataProviderHelper.CreateInputParam("@PasswordAnswer", SqlDbType.NVarChar, passwordAnswer));
                }

                p = new SqlParameter("@ReturnValue", SqlDbType.Int) { Direction = ParameterDirection.ReturnValue };
                cmd.Parameters.Add(p);

                reader = cmd.ExecuteReader(CommandBehavior.SingleRow);

                string password;

                status = -1;

                if (reader.Read())
                {
                    password = reader.GetString(0);
                    passwordFormat = (MembershipPasswordFormat)reader.GetInt32(1);
                }
                else
                {
                    password = null;
                    passwordFormat = 0;
                }

                return password;
            }
            finally
            {
                if (reader != null)
                {
                    reader.Close();

                    status = ((p.Value != null) ? ((int)p.Value) : -1);
                }
            }
        }
    }
}
