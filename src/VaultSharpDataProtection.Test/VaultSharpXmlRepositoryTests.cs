using System.Linq;
using System.Xml.Linq;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp;
using Xunit;
using System;

namespace VaultSharpDataProtection.Test;
public class VaultSharpXmlRepositoryTests
{
    private const string _vaultUri = "http://localhost:8200";
    private const string _token = "hvs.*********************";
    private const string _path = "Keys";
    private const string _mountPoint = "data-protection";

    [Fact(Skip = "Requires a running Vault server")]
    public void StoreAndRetrieveKey_ShouldSucceed()
    {
        var vaultClient = new VaultClient(new VaultClientSettings(_vaultUri, new TokenAuthMethodInfo(_token)));
        var repository = new VaultSharpXmlRepository(vaultClient, _path, _mountPoint);

        var keyXml = """
        <key id="d17a439d-8228-4216-9ea5-16a5424a0788" version="1">
            <creationDate>2024-12-19T10:20:37.0840255Z</creationDate>
            <activationDate>2024-12-19T10:20:30.6281791Z</activationDate>
            <expirationDate>2024-12-26T10:20:30.6281791Z</expirationDate>
            <descriptor deserializerType="Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel.AuthenticatedEncryptorDescriptorDeserializer, Microsoft.AspNetCore.DataProtection, Version=8.0.0.0, Culture=neutral, PublicKeyToken=adb9793829ddae60">
                <descriptor>
                    <encryption algorithm="AES_256_CBC" />
                    <validation algorithm="HMACSHA256" />
                    <masterKey p4:requiresEncryption="true" xmlns:p4="http://schemas.asp.net/2015/03/dataProtection">
                        <value>wlZYX34JjRFEz+1vGZPUI/2hbR5oKtxcq58qh8i2eO7CjdQGuyd3U6+tRIUe1Qzww3kOHZ30Tz8BPcd3nsFEgg==</value>
                    </masterKey>
                </descriptor>
            </descriptor>
        </key>
        """;

        var element = XElement.Parse(keyXml);
        var friendlyName = $"key-{Guid.NewGuid()}";
        repository.StoreElement(element, friendlyName);

        var retrievedElements = repository.GetAllElements();
        Assert.NotNull(retrievedElements);
        Assert.Single(retrievedElements);
        var retrievedElement = retrievedElements.First();
        Assert.Equal(element.ToString(SaveOptions.DisableFormatting), retrievedElement.ToString(SaveOptions.DisableFormatting));
    }
}
