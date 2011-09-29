using System;
using System.Web.Security;
using Mild.MembershipProvider.ViewModels;

namespace Mild.MembershipProvider
{
    public interface IMembershipDataProvidable : IDataProvidable
    {
        void Initialize(string applicationName, SqlConnectionHolder holder, SqlMembershipProvider sqlMembershipProvider, int commandTimeout);
        CreateUserViewModel CreateUser(string salt, string pass, string encodedPasswordAnswer,
            string username, string email, string passwordQuestion, object providerUserKey,
            bool isApproved, bool requiresUniqueEmail, MembershipPasswordFormat passwordFormat);
            bool ChangePassword(string username, string newPasswordQuestion, string encodedPasswordAnswer);
        int ChangePassword(string username, MembershipPasswordFormat passwordFormat, string salt, string pass);
        int ResetPassword(string username, MembershipPasswordFormat passwordFormat, string salt, string encodedPasswordAnswer, string newPassword,
            int maxInvalidPasswordAttempts, int passwordAttemptWindow, bool requiresQuestionAndAnswer);
        int UpdateUser(MembershipUser user, bool requiresUniqueEmail);
        int UnlockUser(string username);
        MembershipUser GetUser(object providerUserKey, bool userIsOnline, string name);
        MembershipUser GetUserByName(string username, bool userIsOnline, string name);
        string GetUsername(string email, bool requiresUniqueEmail);
        bool DeleteUser(string username, bool deleteAllRelatedData);
        MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords, string name);
        int GetNumberOfUsersOnline();
        MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize,
                                                 out int totalRecords, string name);
        MembershipUserCollection FindUserByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords,
                                                 string name);
        bool CheckPassword(string username, bool updateLastLoginActivityDate, bool isPasswordCorrect,
                           DateTime lastLoginDate, DateTime lastActivityDate,
                           int maxInvalidPasswordAttempts, int passwordAttemptWindow);
        int GetPasswordWithFormat(string username, bool updateLastLoginActivityDate, out string password,
                                  out MembershipPasswordFormat passwordFormat, out string passwordSalt, out int failedPasswordAttemptCount,
                                  out int failedPasswordAnswerAttemptCount, out bool isApproved,
                                  out DateTime lastLoginDate, out DateTime lastActivityDate);
        string GetPasswordFromDB(string username, bool requiresQuestionAndAnswer, string passwordAnswer, out int status,
                                 out MembershipPasswordFormat passwordFormat,
                                 int maxInvalidPasswordAttempts, int passwordAttemptWindow);
    }
}
