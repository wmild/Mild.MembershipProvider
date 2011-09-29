// Type: System.Web.Security.MembershipProvider
// Assembly: System.Web.ApplicationServices, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35
// Assembly location: C:\Program Files (x86)\Reference Assemblies\Microsoft\Framework\.NETFramework\v4.0\System.Web.ApplicationServices.dll

using System.Configuration.Provider;
using System.Runtime;
using System.Runtime.CompilerServices;
using System.Web.Configuration;

namespace System.Web.Security
{
    [TypeForwardedFrom("System.Web, Version=2.0.0.0, Culture=Neutral, PublicKeyToken=b03f5f7f11d50a3a")]
    public abstract class MembershipProvider : ProviderBase
    {
        [TargetedPatchingOptOut("Performance critical to inline this type of method across NGen image boundaries")]
        protected MembershipProvider();

        public abstract bool EnablePasswordRetrieval { get; }
        public abstract bool EnablePasswordReset { get; }
        public abstract bool RequiresQuestionAndAnswer { get; }
        public abstract string ApplicationName { get; set; }
        public abstract int MaxInvalidPasswordAttempts { get; }
        public abstract int PasswordAttemptWindow { get; }
        public abstract bool RequiresUniqueEmail { get; }
        public abstract MembershipPasswordFormat PasswordFormat { get; }
        public abstract int MinRequiredPasswordLength { get; }
        public abstract int MinRequiredNonAlphanumericCharacters { get; }
        public abstract string PasswordStrengthRegularExpression { get; }

        public abstract MembershipUser CreateUser(string username, string password, string email,
                                                  string passwordQuestion, string passwordAnswer, bool isApproved,
                                                  object providerUserKey, out MembershipCreateStatus status);

        public abstract bool ChangePasswordQuestionAndAnswer(string username, string password,
                                                             string newPasswordQuestion, string newPasswordAnswer);

        public abstract string GetPassword(string username, string answer);
        public abstract bool ChangePassword(string username, string oldPassword, string newPassword);
        public abstract string ResetPassword(string username, string answer);
        public abstract void UpdateUser(MembershipUser user);
        public abstract bool ValidateUser(string username, string password);
        public abstract bool UnlockUser(string userName);
        public abstract MembershipUser GetUser(object providerUserKey, bool userIsOnline);
        public abstract MembershipUser GetUser(string username, bool userIsOnline);
        public abstract string GetUserNameByEmail(string email);
        public abstract bool DeleteUser(string username, bool deleteAllRelatedData);
        public abstract MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords);
        public abstract int GetNumberOfUsersOnline();

        public abstract MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize,
                                                                 out int totalRecords);

        public abstract MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize,
                                                                  out int totalRecords);

        [TargetedPatchingOptOut("Performance critical to inline this type of method across NGen image boundaries")]
        protected virtual byte[] EncryptPassword(byte[] password);

        protected virtual byte[] EncryptPassword(byte[] password,
                                                 MembershipPasswordCompatibilityMode legacyPasswordCompatibilityMode);

        protected virtual byte[] DecryptPassword(byte[] encodedPassword);
        protected virtual void OnValidatingPassword(ValidatePasswordEventArgs e);
        public event MembershipValidatePasswordEventHandler ValidatingPassword;
    }
}
