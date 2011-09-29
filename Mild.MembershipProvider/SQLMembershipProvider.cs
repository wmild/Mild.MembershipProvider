//------------------------------------------------------------------------------
// <copyright file="SqlMembershipProvider.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//------------------------------------------------------------------------------

using System.Linq;
using Mild.MembershipProvider.Helpers;
using Mild.MembershipProvider.ViewModels;

namespace Mild.MembershipProvider
{
    using  System;
    using  System.Web.Security;
    using  System.Web;
    using  System.Globalization;
    using  System.Collections.Specialized;
    using  System.Security.Cryptography;
    using  System.Text;
    using  System.Text.RegularExpressions;
    using  System.Configuration.Provider;
    using Ninject;

    public class SqlMembershipProvider : MembershipProvider
    {
        public override bool    EnablePasswordRetrieval   { get { return _enablePasswordRetrieval; } }
        public override bool    EnablePasswordReset       { get { return _enablePasswordReset; } }
        public override bool    RequiresQuestionAndAnswer   { get { return _requiresQuestionAndAnswer; } }
        public override bool    RequiresUniqueEmail         { get { return _requiresUniqueEmail; } }
        public override MembershipPasswordFormat PasswordFormat { get { return _passwordFormat; }}
        public override int MaxInvalidPasswordAttempts { get { return _maxInvalidPasswordAttempts; } }
        public override int PasswordAttemptWindow { get { return _passwordAttemptWindow; } }

        private readonly IMembershipDataProvidable _dataSource;
        private SchemaVersion _schemaVersion;

        public SqlMembershipProvider()
        {
            var kernel = new StandardKernel(new ProviderNinjectModule());
            _dataSource = kernel.Get<IMembershipDataProvidable>();        
        }

        public override int MinRequiredPasswordLength
        {
            get { return _minRequiredPasswordLength; }
        }

        public override int MinRequiredNonAlphanumericCharacters
        {
            get { return _minRequiredNonalphanumericCharacters; }
        }

        public override string PasswordStrengthRegularExpression
        {
            get { return _passwordStrengthRegularExpression; }
        }

        public override string ApplicationName
        {
            get { return _appName; }
            set
            {
                if (String.IsNullOrEmpty(value))
                    throw new ArgumentNullException("value");

                if (value.Length > 256)
                    throw new ProviderException( StringResources.GetString( StringResources.ProviderApplicationNameTooLong ) );
                _appName = value;
            }
        }

        private string    _sqlConnectionString;
        private bool      _enablePasswordRetrieval;
        private bool      _enablePasswordReset;
        private bool      _requiresQuestionAndAnswer;
        private string    _appName;
        private bool      _requiresUniqueEmail;
        private int       _maxInvalidPasswordAttempts;
        private int       _commandTimeout;
        private int       _passwordAttemptWindow;
        private int       _minRequiredPasswordLength;
        private int       _minRequiredNonalphanumericCharacters;
        private string    _passwordStrengthRegularExpression;
        private MembershipPasswordFormat _passwordFormat;

        private const int      PasswordSize  = 14;

        public override void Initialize(string name, NameValueCollection config)
        {
            if (config == null)
                throw new ArgumentNullException("config");
            if (String.IsNullOrEmpty(name))
                name = "SqlMembershipProvider";
            ApplySettingsFromAppConfig(config, name);
        }

        private void ApplySettingsFromAppConfig(NameValueCollection config, string name)
        {
            if (string.IsNullOrEmpty(config["description"])) {
                config.Remove("description");
                config.Add("description", StringResources.GetString(StringResources.MembershipSqlProviderDescription));
            }
            base.Initialize(name, config);

            _enablePasswordRetrieval    = SecUtility.GetBooleanValue(config, "enablePasswordRetrieval", false);
            _enablePasswordReset        = SecUtility.GetBooleanValue(config, "enablePasswordReset", true);
            _requiresQuestionAndAnswer  = SecUtility.GetBooleanValue(config, "requiresQuestionAndAnswer", true);
            _requiresUniqueEmail        = SecUtility.GetBooleanValue(config, "requiresUniqueEmail", true);
            _maxInvalidPasswordAttempts = SecUtility.GetIntValue( config, "maxInvalidPasswordAttempts", 5, false, 0 );
            _passwordAttemptWindow      = SecUtility.GetIntValue( config, "passwordAttemptWindow", 10, false, 0 );
            _minRequiredPasswordLength  = SecUtility.GetIntValue( config, "minRequiredPasswordLength", 7, false, 128 );
            _minRequiredNonalphanumericCharacters = SecUtility.GetIntValue( config, "minRequiredNonalphanumericCharacters", 1, true, 128 );

            _passwordStrengthRegularExpression = config["passwordStrengthRegularExpression"];
            if( _passwordStrengthRegularExpression != null )
            {
                _passwordStrengthRegularExpression = _passwordStrengthRegularExpression.Trim();
                if( _passwordStrengthRegularExpression.Length != 0 )
                    DataProviderHelper.ValidateRegularExpression(_passwordStrengthRegularExpression);
            }
            else
                _passwordStrengthRegularExpression = string.Empty;

            if (_minRequiredNonalphanumericCharacters > _minRequiredPasswordLength)
                throw new HttpException(StringResources.GetString(StringResources.MinRequiredNonalphanumericCharactersCanNotBeMoreThanMinRequiredPasswordLength));

            _commandTimeout = SecUtility.GetIntValue( config, "commandTimeout", 30, true, 0 );
            _appName = config["applicationName"];
            if (string.IsNullOrEmpty(_appName))
                _appName = SecUtility.GetDefaultAppName();

            if( _appName.Length > 256 )
            {
                throw new ProviderException(StringResources.GetString(StringResources.ProviderApplicationNameTooLong));
            }

            string membershipPasswordFormatString = config["passwordFormat"] ?? "Hashed";
            _passwordFormat = DataProviderHelper.ConvertToMembershipPasswordFormat(membershipPasswordFormatString);

            if (PasswordFormat == MembershipPasswordFormat.Hashed && EnablePasswordRetrieval)
                throw new ProviderException(StringResources.GetString(StringResources.ProviderCanNotRetrieveHashedPassword));

            string connectionStringName = config["connectionStringName"];
            if (string.IsNullOrEmpty(connectionStringName))
                throw new ProviderException(StringResources.GetString(StringResources.ConnectionNameNotSpecified));
            _sqlConnectionString = SqlConnectionHelper.GetConnectionString(connectionStringName, true, true);
            if (string.IsNullOrEmpty(_sqlConnectionString)) {
                throw new ProviderException(StringResources.GetString(StringResources.ConnectionStringNotFound, connectionStringName));
            }

            SqlConnectionHolder holder = SqlConnectionHelper.GetConnection(_sqlConnectionString, true);

            _dataSource.Initialize(ApplicationName, holder, this, CommandTimeout);
            _schemaVersion = new SchemaVersion(_dataSource, this, holder.Connection);

            config.Remove("connectionStringName");
            config.Remove("enablePasswordRetrieval");
            config.Remove("enablePasswordReset");
            config.Remove("requiresQuestionAndAnswer");
            config.Remove("applicationName");
            config.Remove("requiresUniqueEmail");
            config.Remove("maxInvalidPasswordAttempts");
            config.Remove("passwordAttemptWindow");
            config.Remove("commandTimeout");
            config.Remove("passwordFormat");
            config.Remove("name");
            config.Remove("minRequiredPasswordLength");
            config.Remove("minRequiredNonalphanumericCharacters");
            config.Remove("passwordStrengthRegularExpression");
            if (config.Count > 0) {
                string attribUnrecognized = config.GetKey(0);
                if (!String.IsNullOrEmpty(attribUnrecognized))
                    throw new ProviderException(StringResources.GetString(StringResources.ProviderUnrecognizedAttribute, attribUnrecognized));
            }
        }

        private int CommandTimeout
        {
            get{ return _commandTimeout; }
        }

        public override MembershipUser CreateUser( string username,
                                                   string password,
                                                   string email,
                                                   string passwordQuestion,
                                                   string passwordAnswer,
                                                   bool   isApproved,
                                                   object providerUserKey,
                                                   out    MembershipCreateStatus status )
        {
            if( !SecUtility.ValidateParameter(ref password, 128, checkForNull: true, checkIfEmpty: true))
            {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }

            string salt = SqlMembershipProviderHelper.GenerateSalt();
            string pass = EncodePassword(password, _passwordFormat, salt);
            if ( pass.Length > 128 )
            {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }

            string encodedPasswordAnswer;
            if( passwordAnswer != null )
            {
                passwordAnswer = passwordAnswer.Trim();
            }

            if (!string.IsNullOrEmpty(passwordAnswer)) {
                if( passwordAnswer.Length > 128 )
                {
                    status = MembershipCreateStatus.InvalidAnswer;
                    return null;
                }
                encodedPasswordAnswer = EncodePassword(passwordAnswer.ToLower(CultureInfo.InvariantCulture), _passwordFormat, salt);
            }
            else
                encodedPasswordAnswer = passwordAnswer;
            if (!SecUtility.ValidateParameter(ref encodedPasswordAnswer, 128, checkForNull: RequiresQuestionAndAnswer, checkIfEmpty: true))
            {
                status = MembershipCreateStatus.InvalidAnswer;
                return null;
            }

            if( !SecUtility.ValidateParameter( ref username, 256, checkForNull: true, checkIfEmpty: true, checkForCommas: true))
            {
                status = MembershipCreateStatus.InvalidUserName;
                return null;
            }

            if( !SecUtility.ValidateParameter( ref email, 256, checkForNull: RequiresUniqueEmail, checkIfEmpty: RequiresUniqueEmail) )
            {
                status = MembershipCreateStatus.InvalidEmail;
                return null;
            }

            if( !SecUtility.ValidateParameter( ref passwordQuestion, checkForNull: RequiresQuestionAndAnswer, checkIfEmpty: true, maxSize: 256))
            {
                status = MembershipCreateStatus.InvalidQuestion;
                return null;
            }

            if( providerUserKey != null )
            {
                if( !( providerUserKey is Guid ) )
                {
                    status = MembershipCreateStatus.InvalidProviderUserKey;
                    return null;
                }
            }

            if( password.Length < MinRequiredPasswordLength )
            {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }

            var count = password.Where((t, i) => !char.IsLetterOrDigit(password, i)).Count();

            if( count < MinRequiredNonAlphanumericCharacters )
            {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }

            if( PasswordStrengthRegularExpression.Length > 0 )
            {
                if( !Regex.IsMatch( password, PasswordStrengthRegularExpression ) )
                {
                    status = MembershipCreateStatus.InvalidPassword;
                    return null;
                }
            }

            var e = new ValidatePasswordEventArgs( username, password, true );
            OnValidatingPassword( e );

            if( e.Cancel )
            {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }

            _schemaVersion.Check();

            CreateUserViewModel results = _dataSource.CreateUser(salt, pass, encodedPasswordAnswer, username, email, passwordQuestion, providerUserKey, isApproved, RequiresUniqueEmail, PasswordFormat);
            status = (MembershipCreateStatus)results.Status;
            if (status != MembershipCreateStatus.Success)
                return null;

            providerUserKey = results.UserId;
            DateTime dt = results.Date.ToLocalTime();
            return new MembershipUser(Name, username, providerUserKey,
                    email,passwordQuestion, null, isApproved, false,
                    dt, dt, dt, dt, new DateTime( 1754, 1, 1 ) );
        }

        public override bool ChangePasswordQuestionAndAnswer(string username, string password, string newPasswordQuestion, string newPasswordAnswer)
        {
            SecUtility.CheckParameter(ref username, 256, "username", true, true, true);
            SecUtility.CheckParameter(ref password, 128, "password", true, true);

            string salt;
            MembershipPasswordFormat passwordFormat;
            if (!CheckPassword(username, password, false, false, out salt, out passwordFormat))
                return false;
            SecUtility.CheckParameter(ref newPasswordQuestion, 256, "newPasswordQuestion", RequiresQuestionAndAnswer, RequiresQuestionAndAnswer);
            if( newPasswordAnswer != null )
            {
                newPasswordAnswer = newPasswordAnswer.Trim();
            }

            SecUtility.CheckParameter(ref newPasswordAnswer, 128, "newPasswordAnswer", RequiresQuestionAndAnswer, RequiresQuestionAndAnswer);
            var encodedPasswordAnswer = !string.IsNullOrEmpty(newPasswordAnswer) ? EncodePassword(newPasswordAnswer.ToLower(CultureInfo.InvariantCulture), passwordFormat, salt) : newPasswordAnswer;
            SecUtility.CheckParameter(ref encodedPasswordAnswer, 128, "newPasswordAnswer", RequiresQuestionAndAnswer, RequiresQuestionAndAnswer);

            return _dataSource.ChangePassword(username, newPasswordQuestion, encodedPasswordAnswer);
        }

        public override string GetPassword(string username, string passwordAnswer)
        {
            if ( !EnablePasswordRetrieval )
            {
                throw new NotSupportedException( StringResources.GetString( StringResources.MembershipPasswordRetrievalNotSupported ) );
            }

            SecUtility.CheckParameter(ref username, 256, "username", true, true, true);

            string encodedPasswordAnswer = GetEncodedPasswordAnswer(username, passwordAnswer);
            SecUtility.CheckParameter(ref encodedPasswordAnswer, 128, "passwordAnswer", RequiresQuestionAndAnswer, RequiresQuestionAndAnswer);

            MembershipPasswordFormat passwordFormat;
            int status;

            string pass = GetPasswordFromDB(username, encodedPasswordAnswer, RequiresQuestionAndAnswer, out passwordFormat, out status);

            if ( pass == null )
            {
                DataProviderHelper.ThrowExceptionFromStatus(status);
            }

            return UnEncodePassword( pass, passwordFormat );
        }

        public override bool ChangePassword(string username, string oldPassword, string newPassword)
        {
            SecUtility.CheckParameter(ref username, 256, "username", true, true, true);
            SecUtility.CheckParameter(ref oldPassword, 128, "oldPassword", true, true);
            SecUtility.CheckParameter(ref newPassword, 128, "newPassword", true, true);

            string salt;
            MembershipPasswordFormat passwordFormat;

            if (!CheckPassword( username, oldPassword, false, false, out salt, out passwordFormat))
            {
               return false;
            }

            if( newPassword.Length < MinRequiredPasswordLength )
            {
                throw new ArgumentException(StringResources.GetString(
                              StringResources.PasswordTooShort,
                              "newPassword",
                              MinRequiredPasswordLength.ToString(CultureInfo.InvariantCulture)));
            }

            var count = newPassword.Where((t, i) => !char.IsLetterOrDigit(newPassword, i)).Count();

            if( count < MinRequiredNonAlphanumericCharacters )
            {
                throw new ArgumentException(StringResources.GetString(
                              StringResources.PasswordNeedMoreNonAlphaNumericChars,
                              "newPassword",
                              MinRequiredNonAlphanumericCharacters.ToString(CultureInfo.InvariantCulture)));
            }

            if( PasswordStrengthRegularExpression.Length > 0 )
            {
                if( !Regex.IsMatch( newPassword, PasswordStrengthRegularExpression ) )
                {
                    throw new ArgumentException(StringResources.GetString(StringResources.PasswordDoesNotMatchRegularExpression,
                                                             "newPassword"));
                }
            }

            string pass = EncodePassword(newPassword, passwordFormat, salt);
            if ( pass.Length > 128 )
            {
                throw new ArgumentException(StringResources.GetString(StringResources.MembershipPasswordTooLong), "newPassword");
            }

            var e = new ValidatePasswordEventArgs( username, newPassword, false );
            OnValidatingPassword( e );

            if( e.Cancel )
            {
                throw e.FailureInformation ?? new ArgumentException(StringResources.GetString(StringResources.MembershipCustomPasswordValidationFailure), "newPassword");
            }

            _schemaVersion.Check();

            var status = _dataSource.ChangePassword(username, passwordFormat, salt, pass);

            if ( status != 0 )
            {
                var errText = DataProviderHelper.GetExceptionText(status);
                throw DataProviderHelper.IsStatusDueToBadPassword(status)
                          ? (Exception) new MembershipPasswordException(errText)
                          : new ProviderException(errText);
            }
            return true;
        }

        public override string ResetPassword( string username, string passwordAnswer )
        {
            if ( !EnablePasswordReset )
            {
                throw new NotSupportedException( StringResources.GetString( StringResources.NotConfiguredToSupportPasswordResets ) );
            }

            SecUtility.CheckParameter(ref username, 256, "username", true, true, true);

            string salt;
            MembershipPasswordFormat passwordFormat;
            string passwdFromDB;
            int status;
            int failedPasswordAttemptCount;
            int failedPasswordAnswerAttemptCount;
            bool isApproved;
            DateTime lastLoginDate, lastActivityDate;

            GetPasswordWithFormat(username, false, out status, out passwdFromDB, out passwordFormat, out salt, out failedPasswordAttemptCount,
                                  out failedPasswordAnswerAttemptCount, out isApproved, out lastLoginDate, out lastActivityDate);
            if (status != 0)
            {
                throw DataProviderHelper.IsStatusDueToBadPassword(status) ? (Exception)new MembershipPasswordException(DataProviderHelper.GetExceptionText(status))
                          : new ProviderException(DataProviderHelper.GetExceptionText(status));
            }

            if( passwordAnswer != null )
            {
                passwordAnswer = passwordAnswer.Trim();
            }
            string encodedPasswordAnswer = !string.IsNullOrEmpty(passwordAnswer) ? EncodePassword(passwordAnswer.ToLower(CultureInfo.InvariantCulture), passwordFormat, salt) : passwordAnswer;
            SecUtility.CheckParameter(ref encodedPasswordAnswer, 128, "passwordAnswer", RequiresQuestionAndAnswer, RequiresQuestionAndAnswer);
            string newPassword  = GeneratePassword();

            var e = new ValidatePasswordEventArgs( username, newPassword, false );
            OnValidatingPassword( e );

            if( e.Cancel )
            {
                throw e.FailureInformation ?? new ProviderException(StringResources.GetString(StringResources.MembershipCustomPasswordValidationFailure));
            }

            _schemaVersion.Check();

            status = _dataSource.ResetPassword(username, passwordFormat, salt, encodedPasswordAnswer,
                newPassword, MaxInvalidPasswordAttempts, PasswordAttemptWindow, RequiresQuestionAndAnswer);
            if ( status != 0 )
            {
                DataProviderHelper.ThrowExceptionFromStatus(status);
            }

            return newPassword;
        }

        public override void UpdateUser(MembershipUser user)
        {
            if( user == null )
            {
                throw new ArgumentNullException( "user" );
            }

            string temp = user.UserName;
            SecUtility.CheckParameter(ref temp, 256, "UserName", true, true, true);
            temp = user.Email;
            SecUtility.CheckParameter(ref temp,
                                       256,
                                       "Email",
                                       RequiresUniqueEmail,
                                       RequiresUniqueEmail);
            user.Email = temp;

            _schemaVersion.Check();

            int status = _dataSource.UpdateUser(user, RequiresUniqueEmail);

            if (status != 0)
                throw new ProviderException(DataProviderHelper.GetExceptionText(status));
            return;

        }

        public override bool ValidateUser(string username, string password)
        {
            return SecUtility.ValidateParameter(ref username, 256, checkForNull: true, checkIfEmpty: true, checkForCommas: true) &&
                   SecUtility.ValidateParameter(ref password, 128, checkForNull: true, checkIfEmpty: true) &&
                   CheckPassword(username, password, true, true);
        }

        public override bool UnlockUser( string username )
        {
            SecUtility.CheckParameter(ref username, 256, "username", true, true, true);
            _schemaVersion.Check();
            var status = _dataSource.UnlockUser(username);
            return status == 0;
        }

        public override MembershipUser GetUser( object providerUserKey, bool userIsOnline )
        {
            if( providerUserKey == null )
            {
                throw new ArgumentNullException( "providerUserKey" );
            }

            if ( !( providerUserKey is Guid ) )
            {
                throw new ArgumentException( StringResources.GetString( StringResources.MembershipInvalidProviderUserKey ), "providerUserKey" );
            }

            _schemaVersion.Check();
            return _dataSource.GetUser(providerUserKey, userIsOnline, Name);
        }

        public override MembershipUser GetUser(string username, bool userIsOnline)
        {
            SecUtility.CheckParameter(
                            ref username,
                            256,
                            "username",
                            true,
                            false,
                            true );

            _schemaVersion.Check();
            return _dataSource.GetUserByName(username, userIsOnline, Name);
        }

        public override string GetUserNameByEmail(string email)
        {
            SecUtility.CheckParameter(
                            ref email,
                            256,
                            "email");

            _schemaVersion.Check();
            return _dataSource.GetUsername(email, RequiresUniqueEmail);
        }

        public override bool DeleteUser(string username, bool deleteAllRelatedData)
        {
            SecUtility.CheckParameter(ref username, 256, "username", true, true, true);

            _schemaVersion.Check();
            return _dataSource.DeleteUser(username, deleteAllRelatedData);
        }

        public override MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords)
        {
            DataProviderHelper.CheckPaging(pageIndex, pageSize);
            _schemaVersion.Check();
            return _dataSource.GetAllUsers(pageIndex, pageSize, out totalRecords, Name);
        }

        public override int GetNumberOfUsersOnline()
        {
            return _dataSource.GetNumberOfUsersOnline();
        }

        public override MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            SecUtility.CheckParameter(ref usernameToMatch, 256, "usernameToMatch", true, true);
            DataProviderHelper.CheckPaging(pageIndex, pageSize);
            _schemaVersion.Check();
            return _dataSource.FindUsersByName(usernameToMatch, pageIndex, pageSize, out totalRecords, Name);
        }

        public override MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            SecUtility.CheckParameter(ref emailToMatch, 256, "emailToMatch");
            DataProviderHelper.CheckPaging(pageIndex, pageSize);
            _schemaVersion.Check();
            return _dataSource.FindUserByEmail(emailToMatch, pageIndex, pageSize, out totalRecords, Name);
        }

        private bool CheckPassword( string username, string password, bool updateLastLoginActivityDate, bool failIfNotApproved)
        {
            string                   salt;
            MembershipPasswordFormat passwordFormat;
            return CheckPassword(username, password, updateLastLoginActivityDate, failIfNotApproved, out salt, out passwordFormat);
        }

        private bool CheckPassword( string username, string password, bool updateLastLoginActivityDate, bool failIfNotApproved, out string salt, out MembershipPasswordFormat passwordFormat)
        {
            string              passwdFromDB;
            int                 status;
            int                 failedPasswordAttemptCount;
            int                 failedPasswordAnswerAttemptCount;
            bool                isApproved;
            DateTime            lastLoginDate, lastActivityDate;

            GetPasswordWithFormat(username, updateLastLoginActivityDate, out status, out passwdFromDB, out passwordFormat, out salt, out failedPasswordAttemptCount,
                                  out failedPasswordAnswerAttemptCount, out isApproved, out lastLoginDate, out lastActivityDate);
            if (status != 0)
                return false;
            if (!isApproved && failIfNotApproved)
                return false;

            string encodedPasswd = EncodePassword( password, passwordFormat, salt );

            bool isPasswordCorrect = passwdFromDB.Equals( encodedPasswd );

            if( isPasswordCorrect && failedPasswordAttemptCount == 0 && failedPasswordAnswerAttemptCount == 0 )
                return true;

            _schemaVersion.Check();
            return _dataSource.CheckPassword(username, updateLastLoginActivityDate, isPasswordCorrect, lastLoginDate, lastActivityDate, MaxInvalidPasswordAttempts, PasswordAttemptWindow);
        }

        private void GetPasswordWithFormat( string       username,
                                            bool         updateLastLoginActivityDate,
                                            out int      status,
                                            out string   password,
                                            out MembershipPasswordFormat passwordFormat,
                                            out string   passwordSalt,
                                            out int      failedPasswordAttemptCount,
                                            out int      failedPasswordAnswerAttemptCount,
                                            out bool     isApproved,
                                            out DateTime lastLoginDate,
                                            out DateTime lastActivityDate)
        {
            _schemaVersion.Check();
            status = _dataSource.GetPasswordWithFormat(username, updateLastLoginActivityDate, out password, out passwordFormat, out passwordSalt, out failedPasswordAttemptCount, out failedPasswordAnswerAttemptCount, out isApproved, out lastLoginDate, out lastActivityDate);
        }

        private string GetPasswordFromDB( string       username,
                                          string       passwordAnswer,
                                          bool         requiresQuestionAndAnswer,
                                          out MembershipPasswordFormat      passwordFormat,
                                          out int      status )
        {
            _schemaVersion.Check();
            return _dataSource.GetPasswordFromDB(username, requiresQuestionAndAnswer, passwordAnswer, out status, out passwordFormat, MaxInvalidPasswordAttempts, PasswordAttemptWindow);
        }

        private string GetEncodedPasswordAnswer(string username, string passwordAnswer)
        {
            if( passwordAnswer != null )
            {
                passwordAnswer = passwordAnswer.Trim();
            }
            if (string.IsNullOrEmpty(passwordAnswer))
                return passwordAnswer;
            int status, failedPasswordAttemptCount, failedPasswordAnswerAttemptCount;
            MembershipPasswordFormat passwordFormat;
            string password, passwordSalt;
            bool isApproved;
            DateTime lastLoginDate, lastActivityDate;
            GetPasswordWithFormat(username, false, out status, out password, out passwordFormat, out passwordSalt,
                                  out failedPasswordAttemptCount, out failedPasswordAnswerAttemptCount, out isApproved, out lastLoginDate, out lastActivityDate);
            if (status == 0)
                return EncodePassword(passwordAnswer.ToLower(CultureInfo.InvariantCulture), passwordFormat, passwordSalt);
            throw new ProviderException(DataProviderHelper.GetExceptionText(status));
        }

        public virtual string GeneratePassword()
        {
            return Membership.GeneratePassword(
                      MinRequiredPasswordLength < PasswordSize ? PasswordSize : MinRequiredPasswordLength,
                      MinRequiredNonAlphanumericCharacters );
        }

        private string EncodePassword(string password, MembershipPasswordFormat membershipPasswordFormat, string salt)
        {
            if (membershipPasswordFormat == MembershipPasswordFormat.Clear)
                return password;

            byte[] bIn = Encoding.Unicode.GetBytes(password);
            byte[] bSalt = Convert.FromBase64String(salt);
            var bAll = new byte[bSalt.Length + bIn.Length];
            byte[] bRet;

            Buffer.BlockCopy(bSalt, 0, bAll, 0, bSalt.Length);
            Buffer.BlockCopy(bIn, 0, bAll, bSalt.Length, bIn.Length);
            if (membershipPasswordFormat == MembershipPasswordFormat.Hashed )
            {
                HashAlgorithm s = HashAlgorithm.Create( Membership.HashAlgorithmType );
                bRet = s.ComputeHash(bAll);
            } else
            {
                bRet = EncryptPassword( bAll );
            }

            return Convert.ToBase64String(bRet);
        }

        private string UnEncodePassword(string pass, MembershipPasswordFormat passwordFormat)
        {
            switch (passwordFormat)
            {
                case MembershipPasswordFormat.Clear:
                    return pass;
                case MembershipPasswordFormat.Hashed:
                    throw new ProviderException(StringResources.GetString(StringResources.ProviderCanNotDecodeHashedPassword));
                default:
                    byte[] bIn = Convert.FromBase64String(pass);
                    byte[] bRet = DecryptPassword( bIn );
                    if (bRet == null)
                        return null;
                    return Encoding.Unicode.GetString(bRet, 16, bRet.Length - 16);
            }
        }
    }
}
