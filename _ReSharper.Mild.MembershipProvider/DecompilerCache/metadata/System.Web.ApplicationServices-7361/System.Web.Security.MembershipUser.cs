// Type: System.Web.Security.MembershipUser
// Assembly: System.Web.ApplicationServices, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35
// Assembly location: C:\Program Files (x86)\Reference Assemblies\Microsoft\Framework\.NETFramework\v4.0\System.Web.ApplicationServices.dll

using System;
using System.Runtime;
using System.Runtime.CompilerServices;

namespace System.Web.Security
{
    [TypeForwardedFrom("System.Web, Version=2.0.0.0, Culture=Neutral, PublicKeyToken=b03f5f7f11d50a3a")]
    [Serializable]
    public class MembershipUser
    {
        public MembershipUser(string providerName, string name, object providerUserKey, string email,
                              string passwordQuestion, string comment, bool isApproved, bool isLockedOut,
                              DateTime creationDate, DateTime lastLoginDate, DateTime lastActivityDate,
                              DateTime lastPasswordChangedDate, DateTime lastLockoutDate);

        [TargetedPatchingOptOut("Performance critical to inline this type of method across NGen image boundaries")]
        protected MembershipUser();

        public virtual string UserName { [TargetedPatchingOptOut("Performance critical to inline this type of method across NGen image boundaries")]
        get; }

        public virtual object ProviderUserKey { [TargetedPatchingOptOut("Performance critical to inline this type of method across NGen image boundaries")]
        get; }

        public virtual string Email { [TargetedPatchingOptOut("Performance critical to inline this type of method across NGen image boundaries")]
        get; [TargetedPatchingOptOut("Performance critical to inline this type of method across NGen image boundaries")]
        set; }

        public virtual string PasswordQuestion { [TargetedPatchingOptOut("Performance critical to inline this type of method across NGen image boundaries")]
        get; }

        public virtual string Comment { [TargetedPatchingOptOut("Performance critical to inline this type of method across NGen image boundaries")]
        get; [TargetedPatchingOptOut("Performance critical to inline this type of method across NGen image boundaries")]
        set; }

        public virtual bool IsApproved { [TargetedPatchingOptOut("Performance critical to inline this type of method across NGen image boundaries")]
        get; [TargetedPatchingOptOut("Performance critical to inline this type of method across NGen image boundaries")]
        set; }

        public virtual bool IsLockedOut { [TargetedPatchingOptOut("Performance critical to inline this type of method across NGen image boundaries")]
        get; }

        public virtual DateTime LastLockoutDate { get; }
        public virtual DateTime CreationDate { get; }
        public virtual DateTime LastLoginDate { get; set; }
        public virtual DateTime LastActivityDate { get; set; }
        public virtual DateTime LastPasswordChangedDate { get; }
        public virtual bool IsOnline { get; }

        public virtual string ProviderName { [TargetedPatchingOptOut("Performance critical to inline this type of method across NGen image boundaries")]
        get; }

        [TargetedPatchingOptOut("Performance critical to inline this type of method across NGen image boundaries")]
        public override string ToString();

        public virtual string GetPassword();
        public virtual string GetPassword(string passwordAnswer);
        public virtual bool ChangePassword(string oldPassword, string newPassword);

        public virtual bool ChangePasswordQuestionAndAnswer(string password, string newPasswordQuestion,
                                                            string newPasswordAnswer);

        public virtual string ResetPassword(string passwordAnswer);

        [TargetedPatchingOptOut("Performance critical to inline this type of method across NGen image boundaries")]
        public virtual string ResetPassword();

        public virtual bool UnlockUser();
    }
}
