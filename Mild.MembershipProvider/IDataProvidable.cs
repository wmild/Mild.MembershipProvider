using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Mild.MembershipProvider
{
    public interface IDataProvidable
    {
        int CheckSchemaVersion(string feature);
    }
}
