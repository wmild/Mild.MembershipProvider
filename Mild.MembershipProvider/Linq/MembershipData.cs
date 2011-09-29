using System;
using System.Configuration.Provider;
using System.Linq;
using System.Web.Security;
using Mild.MembershipProvider.Helpers;
using Mild.MembershipProvider.ViewModels;

namespace Mild.MembershipProvider.Linq
{
    public class MembershipData : IMembershipDataProvidable
    {
        private int CommandTimeout { get; set; }
        private SqlConnectionHolder Holder { get; set; }
        private ProviderBase Provider { get; set; }
        private string ApplicationName { get; set; }

        public void Initialize(string applicationName, SqlConnectionHolder holder, SqlMembershipProvider sqlMembershipProvider, int commandTimeout)
        {
            CommandTimeout = commandTimeout;
            Holder = holder;
            Provider = sqlMembershipProvider;
            ApplicationName = applicationName;
        }

        public int CheckSchemaVersion(string feature)
        {
            return 0;
        }

        public CreateUserViewModel CreateUser(string salt, string pass, string encodedPasswordAnswer, string username, string email, string passwordQuestion, object providerUserKey, bool isApproved, bool requiresUniqueEmail, MembershipPasswordFormat passwordFormat)
        {
            var userId = (Guid?)providerUserKey;
            var errorCode = 0;
            bool newUserCreated = false;
            DateTime createDate = DataProviderHelper.RoundToSeconds(DateTime.UtcNow);          
            
            Guid? applicationId;
            CreateApplication(ApplicationName, out applicationId);
            var db = new ProviderDataContext();
            aspnet_User aspnetUser =
                db.aspnet_Users.SingleOrDefault(p => p.LoweredUserName == username && p.ApplicationId == applicationId);
            var newUserId = aspnetUser == null ? (Guid?)null : aspnetUser.UserId;
            if (!newUserId.HasValue)
            {
                try
                {
                    newUserId = aspnet_Users_CreateUser(applicationId, username, false, createDate, newUserId);
                }
                catch (Exception)
                {
                    errorCode = 10;
                }
                newUserCreated = true;
            }
            else
            {
                if (newUserId != userId & userId.HasValue)
                    return new CreateUserViewModel {Status = 6};
            }

            bool membershipExists = db.aspnet_Memberships.Any(p => p.UserId == newUserId);
            if (membershipExists)
                return new CreateUserViewModel { Status = 6 };

            if (requiresUniqueEmail)
            {
                membershipExists =
                    db.aspnet_Memberships.Any(p => p.ApplicationId == applicationId & p.LoweredEmail == email.ToLower());
                if (membershipExists)
                    return new CreateUserViewModel { Status = 7 };
            }

            if (!newUserCreated)
            {
                aspnet_User user = db.aspnet_Users.SingleOrDefault(p => p.UserId == userId);
                user.LastActivityDate = createDate;
            }

            var membership = new aspnet_Membership
            {
                ApplicationId = applicationId.Value,
                UserId = userId.Value,
                Password = pass,
                PasswordSalt = salt,
                Email = email,
                LoweredEmail = email.ToLower(),
                PasswordQuestion = passwordQuestion,
                PasswordAnswer = encodedPasswordAnswer,
                IsApproved = isApproved,
                IsLockedOut = false,
                CreateDate = createDate,
                LastLoginDate = createDate,
                LastPasswordChangedDate = createDate,
                LastLockoutDate = new DateTime(1754,1,1),
                FailedPasswordAttemptCount = 0,
                FailedPasswordAttemptWindowStart = new DateTime(1754,1,1),
                FailedPasswordAnswerAttemptCount = 0,
                FailedPasswordAnswerAttemptWindowStart = new DateTime(1754,1,1)
            };

            db.aspnet_Memberships.InsertOnSubmit(membership);
            db.SubmitChanges();


            if (errorCode < 0 || errorCode > (int)MembershipCreateStatus.ProviderError)
                errorCode = (int)MembershipCreateStatus.ProviderError;

            return new CreateUserViewModel
            {
                Status = errorCode,
                UserId = userId.Value,
                Date = createDate
            };
        }

        private static Guid? aspnet_Users_CreateUser(Guid? applicationId, string username, bool isAnonymous, DateTime lastActivityDate, Guid? userId)
        {
            var db = new ProviderDataContext();
            if (!userId.HasValue)
                userId = Guid.NewGuid();
            else
            {
                if (db.aspnet_Users.Any(p => p.UserId == userId))
                    throw new ProviderException("There is no user with userid " + userId);
            }

            var user = new aspnet_User
                           {
                                       ApplicationId = applicationId.Value,
                                       UserId = userId.Value,
                                       UserName = username,
                                       LoweredUserName = username.ToLower(),
                                       IsAnonymous = isAnonymous,
                                       LastActivityDate = lastActivityDate
                                   };
            db.aspnet_Users.InsertOnSubmit(user);
            db.SubmitChanges();
            return userId;
        }

        private void CreateApplication(string applicationName, out Guid? applicationId)
        {
            throw new NotImplementedException();
        }

        public bool ChangePassword(string username, string newPasswordQuestion, string encodedPasswordAnswer)
        {
            throw new NotImplementedException();
        }

        public int ChangePassword(string username, MembershipPasswordFormat passwordFormat, string salt, string pass)
        {
            throw new NotImplementedException();
        }

        public int ResetPassword(string username, MembershipPasswordFormat passwordFormat, string salt, string encodedPasswordAnswer, string newPassword, int maxInvalidPasswordAttempts, int passwordAttemptWindow, bool requiresQuestionAndAnswer)
        {
            throw new NotImplementedException();
        }

        public int UpdateUser(MembershipUser user, bool requiresUniqueEmail)
        {
            throw new NotImplementedException();
        }

        public int UnlockUser(string username)
        {
            throw new NotImplementedException();
        }

        public MembershipUser GetUser(object providerUserKey, bool userIsOnline, string name)
        {
            throw new NotImplementedException();
        }

        public MembershipUser GetUserByName(string username, bool userIsOnline, string name)
        {
            throw new NotImplementedException();
        }

        public string GetUsername(string email, bool requiresUniqueEmail)
        {
            throw new NotImplementedException();
        }

        public bool DeleteUser(string username, bool deleteAllRelatedData)
        {
            throw new NotImplementedException();
        }

        public MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords, string name)
        {
            throw new NotImplementedException();
        }

        public int GetNumberOfUsersOnline()
        {
            throw new NotImplementedException();
        }

        public MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize, out int totalRecords, string name)
        {
            throw new NotImplementedException();
        }

        public MembershipUserCollection FindUserByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords, string name)
        {
            throw new NotImplementedException();
        }

        public bool CheckPassword(string username, bool updateLastLoginActivityDate, bool isPasswordCorrect, DateTime lastLoginDate, DateTime lastActivityDate, int maxInvalidPasswordAttempts, int passwordAttemptWindow)
        {
            throw new NotImplementedException();
        }

        public int GetPasswordWithFormat(string username, bool updateLastLoginActivityDate, out string password, out MembershipPasswordFormat passwordFormat, out string passwordSalt, out int failedPasswordAttemptCount, out int failedPasswordAnswerAttemptCount, out bool isApproved, out DateTime lastLoginDate, out DateTime lastActivityDate)
        {
            throw new NotImplementedException();
        }

        public string GetPasswordFromDB(string username, bool requiresQuestionAndAnswer, string passwordAnswer, out int status, out MembershipPasswordFormat passwordFormat, int maxInvalidPasswordAttempts, int passwordAttemptWindow)
        {
            throw new NotImplementedException();
        }
    }
}
