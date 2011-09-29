using System;
using System.Configuration.Provider;
using System.Data;
using System.Data.SqlClient;
using Mild.MembershipProvider.Helpers;

namespace Mild.MembershipProvider.Original
{
    public class Data : IDisposable
    {
        protected ProviderBase Provider { get; set; }
        protected SqlConnectionHolder Holder { get; set; }

        public int CheckSchemaVersion(string feature)
        {
            const int version = 1;

            var cmd = new SqlCommand("dbo.aspnet_CheckSchemaVersion", Holder.Connection) { CommandType = CommandType.StoredProcedure };

            var p = new SqlParameter("@Feature", feature);
            cmd.Parameters.Add(p);

            p = new SqlParameter("@CompatibleSchemaVersion", version);
            cmd.Parameters.Add(p);

            p = new SqlParameter("@ReturnValue", SqlDbType.Int) { Direction = ParameterDirection.ReturnValue };
            cmd.Parameters.Add(p);

            cmd.ExecuteNonQuery();

            var iStatus = ((p.Value != null) ? ((int)p.Value) : -1);
            if (iStatus != 0)
            {
                throw new ProviderException(
                    StringResources.GetString(StringResources.ProviderSchemaVersionNotMatch,
                                                Provider.ToString(), version.ToString()));
            }
            return iStatus;
        }

        public void Dispose()
        {
            if (Holder != null)
                Holder.Close();
        }

    }
}
