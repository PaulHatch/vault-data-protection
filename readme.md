
# Vault Data Protection

[![NuGet version (VaultSharpDataProtection)](https://img.shields.io/nuget/v/VaultSharpDataProtection.svg?style=flat-square)](https://www.nuget.org/packages/VaultSharpDataProtection/)

This package provides an XmlRepository implementation which can be used to store
[ASP.NET Data Protection](https://docs.microsoft.com/en-us/aspnet/core/security/data-protection/introduction) keys
in Hashcorp Vault using the [VaultSharp](https://github.com/rajanadar/VaultSharp) client.

## Usage

In your Startup.cs when configuring data protection use one of the `PersistKeysToVault`
extension methods:

```csharp
public void ConfigureServices(IServiceCollection services)
{
    var vaultUri = Configuration.GetConnectionString("vault");
    var vaultToken = Environment.GetEnvironmentVariable("VAULT_TOKEN");

    services.AddDataProtection()
        .PersistKeysToVault(vaultUri, vaultToken, "DataProtectionsKeys", "appSecrets");
    // ...
}
```

