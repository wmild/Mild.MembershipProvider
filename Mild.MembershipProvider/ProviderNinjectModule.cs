using Mild.MembershipProvider.Original;
using Ninject.Modules;

namespace Mild.MembershipProvider
{
    class ProviderNinjectModule : NinjectModule
    {
        public override void Load()
        {
            Bind<IMembershipDataProvidable>().To<Original.MembershipData>();
            Bind<IRoleDataProvidable>().To<Original.RoleData>();
        }
    }
}
