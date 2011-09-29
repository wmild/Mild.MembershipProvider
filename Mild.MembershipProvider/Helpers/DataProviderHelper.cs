using System;
using System.Configuration.Provider;
using System.Data;
using System.Data.SqlClient;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Security;

namespace Mild.MembershipProvider.Helpers
{
    public static class DataProviderHelper
    {
        public static DateTime RoundToSeconds(DateTime dt)
        {
            return new DateTime(dt.Year, dt.Month, dt.Day, dt.Hour, dt.Minute, dt.Second);
        }

        public static SqlParameter CreateInputParam(string paramName, SqlDbType dbType, object objValue)
        {

            var param = new SqlParameter(paramName, dbType);

            if (objValue == null)
            {
                param.IsNullable = true;
                param.Value = DBNull.Value;
            }
            else
            {
                param.Value = objValue;
            }

            return param;
        }

        public static string GetExceptionText(int status)
        {
            string key;
            switch (status)
            {
                case 0:
                    return String.Empty;
                case 1:
                    key = StringResources.MembershipUserNotFound;
                    break;
                case 2:
                    key = StringResources.MembershipWrongPassword;
                    break;
                case 3:
                    key = StringResources.MembershipWrongAnswer;
                    break;
                case 4:
                    key = StringResources.MembershipInvalidPassword;
                    break;
                case 5:
                    key = StringResources.MembershipInvalidQuestion;
                    break;
                case 6:
                    key = StringResources.MembershipInvalidAnswer;
                    break;
                case 7:
                    key = StringResources.MembershipInvalidEmail;
                    break;
                case 99:
                    key = StringResources.MembershipAccountLockOut;
                    break;
                default:
                    key = StringResources.ProviderError;
                    break;
            }
            return StringResources.GetString(key);
        }

        public static string EncodePassword(string pass, MembershipPasswordFormat passwordFormat, string salt)
        {
            if (passwordFormat == MembershipPasswordFormat.Clear)
                return pass;

            byte[] bIn = Encoding.Unicode.GetBytes(pass);
            byte[] bSalt = Convert.FromBase64String(salt);
            var bAll = new byte[bSalt.Length + bIn.Length];
            byte[] bRet;

            Buffer.BlockCopy(bSalt, 0, bAll, 0, bSalt.Length);
            Buffer.BlockCopy(bIn, 0, bAll, bSalt.Length, bIn.Length);
            if (passwordFormat ==  MembershipPasswordFormat.Hashed)
            {
                HashAlgorithm s = HashAlgorithm.Create(Membership.HashAlgorithmType);
                bRet = s.ComputeHash(bAll);
            }
            else
            {
                bRet = EncryptPassword(bAll);
            }

            return Convert.ToBase64String(bRet);
        }

        //To implement encryption, this class needs to be implemented.
        private static byte[] EncryptPassword(byte[] password)
        {
            return new byte[]{};
        }

        public static string GetNullableString(SqlDataReader reader, int col)
        {
            return reader.IsDBNull(col) == false ? reader.GetString(col) : null;
        }

        public static bool IsStatusDueToBadPassword(int status)
        {
            return (status >= 2 && status <= 6 || status == 99);
        }

        public static void ThrowExceptionFromStatus(int status)
        {
            string errText = DataProviderHelper.GetExceptionText(status);

            if (DataProviderHelper.IsStatusDueToBadPassword(status))
            {
                throw new MembershipPasswordException(errText);
            }
            else
            {
                throw new ProviderException(errText);
            }
        }

        public static void CheckPaging(int pageIndex, int pageSize)
        {
            if (pageIndex < 0)
                throw new ArgumentException(StringResources.GetString(StringResources.PageIndexBad), "pageIndex");
            if (pageSize < 1)
                throw new ArgumentException(StringResources.GetString(StringResources.PageSizeBad), "pageSize");

            long upperBound = (long)pageIndex * pageSize + pageSize - 1;
            if (upperBound > Int32.MaxValue)
                throw new ArgumentException(StringResources.GetString(StringResources.PageIndexPageSizeBad), "pageIndex and pageSize");
        }

        public static int GetReturnValue(SqlCommand cmd)
        {
            foreach (SqlParameter param in cmd.Parameters)
            {
                if (param.Direction == ParameterDirection.ReturnValue && param.Value != null && param.Value is int)
                    return (int)param.Value;
            }
            return -1;
        }

        public static void ValidateRegularExpression(string expression)
        {
            try
            {
                var regex = new Regex(expression);
            }
            catch (ArgumentException e)
            {
                throw new ProviderException(e.Message, e);
            }
        }

        public static MembershipPasswordFormat ConvertToMembershipPasswordFormat(string membershipPasswordFormatString)
        {
            switch (membershipPasswordFormatString)
            {
                case "Clear":
                    return MembershipPasswordFormat.Clear;
                case "Encrypted":
                    return MembershipPasswordFormat.Encrypted;
                case "Hashed":
                    return MembershipPasswordFormat.Hashed;
                default:
                    throw new ProviderException(StringResources.GetString(StringResources.ProviderBadPasswordFormat));
            }
        }


    }
}
