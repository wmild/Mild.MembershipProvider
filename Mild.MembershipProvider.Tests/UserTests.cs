using System.Configuration;
using System.Web.Security;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Mild.MembershipProvider.Tests
{
    [TestClass]
    public class UserTests
    {
        [TestMethod]
        public void CreateAndDeleteUser()
        {
            string username = ConfigurationManager.AppSettings["UnitTestUsername"];
            string password = ConfigurationManager.AppSettings["UnitTestPassword"];
            string email = ConfigurationManager.AppSettings["UnitTestEmail"];

            Membership.CreateUser(username, password, email);
            Membership.DeleteUser(username);
        }
    }
}
