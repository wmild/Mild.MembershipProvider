//------------------------------------------------------------------------------
// <copyright file="SqlConnectionHelper.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//------------------------------------------------------------------------------

using System.Configuration;

namespace Mild.MembershipProvider.Helpers
{
    /// <devdoc>
    /// </devdoc>
    internal static class SqlConnectionHelper
    {
        internal const string SStrUpperDataDirWithToken = "|DATADIRECTORY|";

        /// <devdoc>
        /// </devdoc>
        internal static SqlConnectionHolder GetConnection(string connectionString, bool revertImpersonation)
        {
            var holder = new SqlConnectionHolder(connectionString);
            var closeConn = true;
            try
            {
                holder.Open(revertImpersonation);
                closeConn = false;
            }
            finally
            {
                if (closeConn)
                {
                    holder.Close();
                    holder = null;
                }
            }
            return holder;
        }

        internal static string GetConnectionString(string specifiedConnectionString, bool lookupConnectionString, bool appLevel)
        {
            if (string.IsNullOrEmpty(specifiedConnectionString))
                return null;

            string connectionString = null;

            /////////////////////////////////////////
            // Step 1: Check <connectionStrings> config section for this connection string
            if (lookupConnectionString)
            {
                ConnectionStringSettings connObj = ConfigurationManager.ConnectionStrings[specifiedConnectionString];
                if (connObj != null)
                    connectionString = connObj.ConnectionString;

                if (connectionString == null)
                    return null;
            }
            else
            {
                connectionString = specifiedConnectionString;
            }

            return connectionString;
        }
    }
}

