using System.Configuration.Provider;
using System.Data.SqlClient;
using Mild.MembershipProvider.Helpers;
using Ninject;

namespace Mild.MembershipProvider
{
    public class SchemaVersion
    {
        private readonly ProviderBase _provider;
        private readonly SqlConnection _connection;
        private readonly IDataProvidable _dataSource;

        [Inject]
        public SchemaVersion(IDataProvidable dataSource, ProviderBase provider, SqlConnection connection)
        {
            _dataSource = dataSource;
            _provider = provider;
            _connection = connection;
        }

        public void Check()
        {
            const string version = "1";

            lock (_provider)
            {
                string[] features = {"Common", "Membership"};
                foreach (string feature in features)
                {
                    int iStatus = _dataSource.CheckSchemaVersion(feature);
                    if (iStatus != 0)
                    {
                        throw new ProviderException(
                            StringResources.GetString(StringResources.ProviderSchemaVersionNotMatch, _provider.ToString(), version));
                    }
                   
                }
            }
        }
    }
}
