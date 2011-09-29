using System;
using System.Security.Cryptography;

namespace Mild.MembershipProvider.Helpers
{
    public class SqlMembershipProviderHelper
    {
        internal static string GenerateSalt()
        {
            var buf = new byte[16];
            (new RNGCryptoServiceProvider()).GetBytes(buf);
            return Convert.ToBase64String(buf);
        }

    }
}
