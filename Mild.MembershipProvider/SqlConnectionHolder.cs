using System;
using System.Data.SqlClient;
using System.Web.Hosting;
using Mild.MembershipProvider.Helpers;

namespace Mild.MembershipProvider
{
    public sealed class SqlConnectionHolder
    {
        private readonly SqlConnection _connection;
        private bool _opened;

        internal SqlConnection Connection
        {
            get { return _connection; }
        }

        internal SqlConnectionHolder(string connectionString)
        {
            try
            {
                _connection = new SqlConnection(connectionString);
            }
            catch (ArgumentException e)
            {
                throw new ArgumentException(StringResources.GetString(StringResources.SqlErrorConnectionString), "connectionString", e);
            }
        }

        internal void Open(bool revertImpersonate)
        {
            if (_opened)
                return; // Already opened

            if (revertImpersonate)
            {
                using (HostingEnvironment.Impersonate())
                {
                    Connection.Open();
                }
            }
            else
            {
                Connection.Open();
            }

            _opened = true; // Open worked!
        }

        internal void Close()
        {
            if (!_opened) // Not open!
                return;
            // Close connection
            Connection.Close();
            _opened = false;
        }
    }
}
