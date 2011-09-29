//------------------------------------------------------------------------------
// <copyright file="SqlRoleProvider.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//------------------------------------------------------------------------------


using Mild.MembershipProvider.Helpers;

namespace Mild.MembershipProvider
{
    using  System;
    using  System.Web.Security;
    using  System.Collections.Specialized;
    using  System.Configuration.Provider;
    using Ninject;


    public class SqlRoleProvider : RoleProvider
    {
        private string  _appName;
        private string  _sqlConnectionString;
        private int     _commandTimeout;

        private readonly IRoleDataProvidable _dataSource;
        private SchemaVersion _schemaVersion;

        public SqlRoleProvider()
        {
            var kernel = new StandardKernel(new ProviderNinjectModule());
            _dataSource = kernel.Get<IRoleDataProvidable>();        
        }

        private int CommandTimeout
        {
            get{ return _commandTimeout; }
        }


        public override  void Initialize(string name, NameValueCollection config){
            if (config == null)
               throw new ArgumentNullException("config");

            if (String.IsNullOrEmpty(name))
                name = "SqlRoleProvider";
            if (string.IsNullOrEmpty(config["description"])) {
                config.Remove("description");
                config.Add("description", StringResources.GetString(StringResources.RoleSqlProviderDescription));
            }
            base.Initialize(name, config);

            _commandTimeout = SecUtility.GetIntValue( config, "commandTimeout", 30, true, 0 );

            string temp = config["connectionStringName"];
            if (string.IsNullOrEmpty(temp))
                throw new ProviderException(StringResources.GetString(StringResources.ConnectionNameNotSpecified));
            _sqlConnectionString = SqlConnectionHelper.GetConnectionString(temp, true, true);
            if (string.IsNullOrEmpty(_sqlConnectionString)) {
                throw new ProviderException(StringResources.GetString(StringResources.ConnectionStringNotFound, temp));
            }

            SqlConnectionHolder holder = SqlConnectionHelper.GetConnection(_sqlConnectionString, true);
            _dataSource.Initialize(ApplicationName, holder, this, CommandTimeout);

            _schemaVersion = new SchemaVersion(_dataSource, this, holder.Connection);

            _appName = config["applicationName"];
            if (string.IsNullOrEmpty(_appName))
                _appName = SecUtility.GetDefaultAppName();

            if( _appName.Length > 256 )
            {
                throw new ProviderException(StringResources.GetString(StringResources.ProviderApplicationNameTooLong));
            }

            config.Remove("connectionStringName");
            config.Remove("applicationName");
            config.Remove("commandTimeout");
            if (config.Count > 0)
            {
                string attribUnrecognized = config.GetKey(0);
                if (!String.IsNullOrEmpty(attribUnrecognized))
                    throw new ProviderException(StringResources.GetString(StringResources.ProviderUnrecognizedAttribute, attribUnrecognized));
            }
        }

        public override bool IsUserInRole(string username, string roleName)
        {
            SecUtility.CheckParameter(ref roleName, 256, "roleName", true, true, true);
            SecUtility.CheckParameter(ref username, 256, "username", true, false, true);
            if (username.Length < 1)
                return false;

            _schemaVersion.Check();
            return _dataSource.IsUserInRole(roleName, username);
        }

        public override  string [] GetRolesForUser(string username)
        {
            SecUtility.CheckParameter(ref username, 256, "username", true, false, true);
            if (username.Length < 1)
                return new string[0];

            _schemaVersion.Check();
            return _dataSource.GetRolesForUser(username);
        }

        public override void CreateRole(string roleName)
        {
            SecUtility.CheckParameter(ref roleName, 256, "roleName", true, true, true);
            _schemaVersion.Check();
            _dataSource.CreateRole(roleName);
        }

        public override bool DeleteRole(string roleName, bool throwOnPopulatedRole)
        {
            SecUtility.CheckParameter(ref roleName, 256, "roleName", true, true, true);
            _schemaVersion.Check();
            return _dataSource.DeleteRole(roleName, throwOnPopulatedRole);
        }

        public override  bool RoleExists(string roleName)
        {
            SecUtility.CheckParameter(ref roleName, 256, "roleName", true, true, true);

            _schemaVersion.Check();
            return _dataSource.RoleExists(roleName);
        }

        public override void AddUsersToRoles(string[] usernames, string[] roleNames)
        {
            SecUtility.CheckArrayParameter(ref roleNames, true, true, true, 256, "roleNames");
            SecUtility.CheckArrayParameter(ref usernames, true, true, true, 256, "usernames");

            _schemaVersion.Check();
            _dataSource.AddUsersToRoles(roleNames, usernames);
        }

        public override void RemoveUsersFromRoles(string[] usernames, string[] roleNames)
        {
            SecUtility.CheckArrayParameter(ref roleNames, true, true, true, 256, "roleNames");
            SecUtility.CheckArrayParameter(ref usernames, true, true, true, 256, "usernames");

            _schemaVersion.Check();
            _dataSource.RemoveUsersFromRoles(roleNames, usernames);
        }

        public override  string [] GetUsersInRole(string roleName)
        {
            SecUtility.CheckParameter(ref roleName, 256, "roleName", true, true, true);

            _schemaVersion.Check();
            return _dataSource.GetUsersInRole(roleName);
        }

        public override  string [] GetAllRoles()
        {
            _schemaVersion.Check();
            return _dataSource.GetAllRoles();
        }

        public override string[] FindUsersInRole(string roleName, string usernameToMatch)
        {
            SecUtility.CheckParameter(ref roleName, 256, "roleName", true, true, true);
            SecUtility.CheckParameter(ref usernameToMatch, 256, "usernameToMatch", true, true);

            _schemaVersion.Check();
            return _dataSource.FindUsersInRole(roleName, usernameToMatch);
        }

        public override  string ApplicationName
        {
            get { return _appName; }
            set {
                _appName = value;

                if ( _appName.Length > 256 )
                {
                    throw new ProviderException( StringResources.GetString( StringResources.ProviderApplicationNameTooLong ) );
                }
            }
        }
    }
}



