using System;
using System.Configuration.Provider;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using Mild.MembershipProvider.Helpers;

namespace Mild.MembershipProvider.Linq
{
    public class Data : IDisposable
    {
        protected ProviderBase Provider { get; set; }
        protected SqlConnectionHolder Holder { get; set; }

        public int CheckSchemaVersion(string feature)
        {
            const int version = 1;

            var db = new ProviderDataContext();
            var exists = db.aspnet_SchemaVersions.Any(p => p.Feature == feature.ToLower() & p.CompatibleSchemaVersion == version.ToString());
            var iStatus = exists ? 0 : 1;

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
