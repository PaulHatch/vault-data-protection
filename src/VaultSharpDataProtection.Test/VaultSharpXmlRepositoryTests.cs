using System.Linq;
using System.Xml.Linq;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp;
using Xunit;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.DataProtection.Repositories;

namespace VaultSharpDataProtection.Test;
public class VaultSharpXmlRepositoryTests
{
    private const string _vaultUri = "http://localhost:8200";
    private const string _token = "hvs.";
    private const string _path = "Keys";
    private const string _mountPoint = "data-protection";

    [Fact(Skip = "Requires a running Vault server")]
    public async Task StoreAndRetrieveKey_ShouldSucceed()
    {
        await WithVaultCleanup((repository) =>
        {
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
        });
    }

    [Theory(Skip = "Requires a running Vault server")]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task DeleteElements(bool delete1, bool delete2)
    {
        await WithVaultCleanup((repository) =>
        {
            var key1 = Guid.NewGuid().ToString();
            var key1Element = XElement.Parse($"""<key id="{key1}" version="1"></key>""");
            repository.StoreElement(key1Element, friendlyName: $"key-{key1}");

            var key2 = Guid.NewGuid().ToString();
            var key2Element = XElement.Parse($"""<key id="{key2}" version="2"></key>""");
            repository.StoreElement(key2Element, friendlyName: $"key-{key2}");

            var ranSelector = false;

            var deletionResult = repository.DeleteElements(deletableElements =>
            {
                ranSelector = true;
                Assert.Equal(2, deletableElements.Count);

                foreach (var element in deletableElements)
                {
                    string id = element.Element.Attribute("id").Value;
                    if (key1.Equals(id))
                    {
                        element.DeletionOrder = delete1 ? 1 : null;
                    }

                    if (key2.Equals(id))
                    {
                        element.DeletionOrder = delete2 ? 2 : null;
                    }
                }
            });

            Assert.True(deletionResult);
            Assert.True(ranSelector);

            var elementSet = new HashSet<string>(repository.GetAllElements().Select(e => e.Attribute("id").Value));

            Assert.InRange(elementSet.Count, 0, 2);

            Assert.Equal(!delete1, elementSet.Contains(key1));
            Assert.Equal(!delete2, elementSet.Contains(key2));
        });
    }

    [Fact(Skip = "Requires a running Vault server")]
    public async Task DeleteElementsWithOutOfBandDeletion()
    {
        await WithVaultCleanup((repository, client) =>
        {
            var key1 = Guid.NewGuid().ToString();
            var key1Element = XElement.Parse($"""<key id="{key1}" version="1"></key>""");
            repository.StoreElement(key1Element, friendlyName: $"key-{key1}");


            var elements = repository.GetAllElements();
            Assert.NotNull(elements);
            Assert.True(elements.Count == 1);
            Assert.Contains(elements, e => e.Attribute("id")?.Value == key1);

            var ranSelector = false;
            var deletionResult = repository.DeleteElements(deletableElements =>
            {
                ranSelector = true;
                client.V1.Secrets.KeyValue.V2.DeleteSecretVersionsAsync(_path, [1], _mountPoint).GetAwaiter().GetResult();
                Assert.Single(deletableElements);
                deletableElements.First().DeletionOrder = 1;
            });

            Assert.True(deletionResult);
            Assert.True(ranSelector);

            var remainingElements = repository.GetAllElements();
            Assert.DoesNotContain(remainingElements, e => e.Attribute("id")?.Value == key1);
        });
    }

    private static async Task WithVaultCleanup(Action<IDeletableXmlRepository> testCode)
    {
        VaultClient client = new(new VaultClientSettings(_vaultUri, new TokenAuthMethodInfo(_token)));
        try
        {
            await client.V1.Secrets.KeyValue.V2.DeleteMetadataAsync(_path, _mountPoint);
            var repository = new VaultSharpXmlRepository(client, _path, _mountPoint);
            testCode(repository);
        }
        finally
        {
            await client.V1.Secrets.KeyValue.V2.DeleteMetadataAsync(_path, _mountPoint);
        }
    }

    private static async Task WithVaultCleanup(Action<IDeletableXmlRepository, VaultClient> testCode)
    {
        VaultClient client = new(new VaultClientSettings(_vaultUri, new TokenAuthMethodInfo(_token)));
        try
        {
            await client.V1.Secrets.KeyValue.V2.DeleteMetadataAsync(_path, _mountPoint);
            var repository = new VaultSharpXmlRepository(client, _path, _mountPoint);
            testCode(repository, client);
        }
        finally
        {
            await client.V1.Secrets.KeyValue.V2.DeleteMetadataAsync(_path, _mountPoint);
        }
    }
}
