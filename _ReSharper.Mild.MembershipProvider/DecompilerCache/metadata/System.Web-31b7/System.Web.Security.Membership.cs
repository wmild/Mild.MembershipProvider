// Type: System.Web.Security.Membership
// Assembly: System.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a
// Assembly location: C:\Program Files (x86)\Reference Assemblies\Microsoft\Framework\.NETFramework\v4.0\System.Web.dll

using System.Runtime;

namespace System.Web.Security
{
    public static class Membership
    {
        public static bool EnablePasswordRetrieval { get; }
        public static bool EnablePasswordReset { get; }
        public static bool RequiresQuestionAndAnswer { get; }
        public static int UserIsOnlineTimeWindow { get; }
        public static MembershipProviderCollection Providers { get; }
        public static MembershipProvider Provider { get; }
        public static string HashAlgorithmType { get; }
        public static int MaxInvalidPasswordAttempts { get; }
        public static int PasswordAttemptWindow { get; }
        public static int MinRequiredPasswordLength { get; }
        public static int MinRequiredNonAlphanumericCharacters { get; }
        public static string PasswordStrengthRegularExpression { get; }
        public static string ApplicationName { get; set; }

        [TargetedPatchingOptOut("Performance critical to inline this type of method across NGen image boundaries")]
        public static MembershipUser CreateUser(string username, string password);

        public static MembershipUser CreateUser(string username, string password, string email);

        [TargetedPatchingOptOut("Performance critical to inline this type of method across NGen image boundaries")]
        public static MembershipUser CreateUser(string username, string password, string email, string passwordQuestion,
                                                string passwordAnswer, bool isApproved,
                                                out MembershipCreateStatus status);

        public static MembershipUser CreateUser(string username, string password, string email, string passwordQuestion,
                                                string passwordAnswer, bool isApproved, object providerUserKey,
                                                out MembershipCreateStatus status);

        public static bool ValidateUser(string username, string password);
        public static MembershipUser GetUser();
        public static MembershipUser GetUser(bool userIsOnline);

        [TargetedPatchingOptOut("Performance critical to inline this type of method across NGen image boundaries")]
        public static MembershipUser GetUser(string username);

        public static MembershipUser GetUser(string username, bool userIsOnline);

        [TargetedPatchingOptOut("Performance critical to inline this type of method across NGen image boundaries")]
        public static MembershipUser GetUser(object providerUserKey);

        public static MembershipUser GetUser(object providerUserKey, bool userIsOnline);
        public static string GetUserNameByEmail(string emailToMatch);
        public static bool DeleteUser(string username);
        public static bool DeleteUser(string username, bool deleteAllRelatedData);
        public static void UpdateUser(MembershipUser user);
        public static MembershipUserCollection GetAllUsers();
        public static MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords);
        public static int GetNumberOfUsersOnline();
        public static string GeneratePassword(int length, int numberOfNonAlphanumericCharacters);

        public static MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize,
                                                               out int totalRecords);

        public static MembershipUserCollection FindUsersByName(string usernameToMatch);

        public static MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize,
                                                                out int totalRecords);

        public static MembershipUserCollection FindUsersByEmail(string emailToMatch);
        public static event MembershipValidatePasswordEventHandler ValidatingPassword;
    }
}
