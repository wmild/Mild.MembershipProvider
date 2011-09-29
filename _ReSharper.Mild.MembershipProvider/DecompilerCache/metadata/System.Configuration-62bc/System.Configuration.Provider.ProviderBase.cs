// Type: System.Configuration.Provider.ProviderBase
// Assembly: System.Configuration, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a
// Assembly location: C:\Program Files (x86)\Reference Assemblies\Microsoft\Framework\.NETFramework\v4.0\System.configuration.dll

using System.Collections.Specialized;

namespace System.Configuration.Provider
{
    public abstract class ProviderBase
    {
        public virtual string Name { get; }
        public virtual string Description { get; }
        public virtual void Initialize(string name, NameValueCollection config);
    }
}
