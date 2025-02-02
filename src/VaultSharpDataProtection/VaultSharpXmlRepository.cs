using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.Repositories;
using VaultSharp;
using VaultSharp.Core;
using VaultSharp.V1.SecretsEngines.KeyValue.V2;

namespace VaultSharpDataProtection;

/// <summary>
/// Provides an <see cref="IXmlRepository"/> implementation for storing
/// data protection keys in Vault using the VaultSharp client.
/// </summary>
/// <seealso cref="Microsoft.AspNetCore.DataProtection.Repositories.IXmlRepository" />
public class VaultSharpXmlRepository : IDeletableXmlRepository
{
    private static readonly TaskFactory _factory =
        new(
            CancellationToken.None,
            TaskCreationOptions.None,
            TaskContinuationOptions.None,
            TaskScheduler.Default);

    private readonly IVaultClient _vault;
    private readonly string _path;
    private readonly string _mountPoint;
    private readonly IKeyValueSecretsEngineV2 _v2Api;

    /// <summary>
    /// Initializes a new instance of the <see cref="VaultSharpXmlRepository"/> class.
    /// </summary>
    /// <param name="vault">The vault client to use.</param>
    /// <param name="path">The path store keys under.</param>
    /// <param name="mountPoint">The Vault key/value mount point.</param>
    public VaultSharpXmlRepository(IVaultClient vault, string path, string mountPoint)
    {
        _vault = vault;
        _v2Api = _vault.V1.Secrets.KeyValue.V2;
        _path = path;
        _mountPoint = mountPoint;
    }


    /// <inheritdoc/>
    public IReadOnlyCollection<XElement> GetAllElements()
    {
        try
        {
            var response = RunSync(async () => await _v2Api.ReadSecretAsync(_path, null, _mountPoint));
            return response.Data.Data.Values.Select(ParseElement).ToList().AsReadOnly();
        }
        catch (VaultApiException e) when (e.StatusCode == 404)
        {
            return [];
        }
    }

    /// <inheritdoc/>
    public void StoreElement(XElement element, string friendlyName)
    {
        RunSync(async () =>
        {
            int? version;
            IDictionary<string, object> value;
            try
            {
                var response = await _v2Api.ReadSecretAsync(_path, null, _mountPoint);
                version = response.Data.Metadata.Version;
                value = response.Data.Data;
            }
            catch (VaultApiException e) when (e.StatusCode == 404)
            {
                version = null;
                value = new Dictionary<string, object>();
            }

            value[friendlyName] = element.ToString(SaveOptions.DisableFormatting);
            await _v2Api.WriteSecretAsync(_path, value, version, _mountPoint);
        });
    }

    private static T RunSync<T>(Func<Task<T>> method)
    {
        return _factory.StartNew(method)
                       .Unwrap()
                       .GetAwaiter()
                       .GetResult();
    }

    private static void RunSync(Func<Task> method)
    {
        _factory.StartNew(method)
                .Unwrap()
                .GetAwaiter()
                .GetResult();
    }

    /// <inheritdoc/>
    public bool DeleteElements(Action<IReadOnlyCollection<IDeletableElement>> chooseElements)
    {
        ArgumentNullException.ThrowIfNull(chooseElements);
        try
        {
            return RunSync(async () =>
            {
                var response = await _v2Api.ReadSecretAsync(_path, null, _mountPoint);
                int currentVersion = response.Data.Metadata.Version;
                IDictionary<string, object> value = response.Data.Data;

                if (value.Count < 1 || currentVersion < 1)
                {
                    return false;
                }

                var deletableElements = value.Select(kv =>
                {
                    XElement element = ParseElement(kv.Value);
                    var id = element.Attribute("id")?.Value;
                    if (string.IsNullOrWhiteSpace(id) || id.Equals(kv.Key.Remove(0, 4), StringComparison.OrdinalIgnoreCase) is false)
                    {
                        throw new InvalidOperationException("Element is missing the 'id' attribute.");
                    }
                    return new DeletableElement(kv.Key, element);
                }).ToList();

                chooseElements(deletableElements);

                var elementsToDelete = deletableElements.Where(e => e.DeletionOrder.HasValue)
                                                        .OrderBy(e => e.DeletionOrder.GetValueOrDefault())
                                                        .ToList();

                if (elementsToDelete is not null && elementsToDelete.Count > 0)
                {
                    foreach (var element in elementsToDelete)
                    {
                        value.Remove(element.Key);
                    }
                    List<int> versionsToDelete = Enumerable.Range(1, currentVersion).ToList();
                    try
                    {
                        await _v2Api.DeleteSecretVersionsAsync(_path, versionsToDelete, _mountPoint);
                        await _v2Api.WriteSecretAsync(_path, value, currentVersion, _mountPoint);
                    }
                    catch
                    {
                        await _v2Api.UndeleteSecretVersionsAsync(_path, versionsToDelete, _mountPoint);
                        return false;
                    }
                }
                return true;
            });
        }
        catch
        {
            return false;
        }
    }

    private static XElement ParseElement(object value)
    {
        return value switch
        {
            string v => XElement.Parse(v),
            JsonElement { ValueKind: JsonValueKind.String } j when j.GetString() is { } s => XElement.Parse(s),
            _ => throw new InvalidCastException($"Expected JSON string, but got {value.GetType()}.")
        };
    }
    private sealed class DeletableElement(string key, XElement element) : IDeletableElement
    {
        public XElement Element { get; } = element;
        public string Key { get; } = key;
        public int? DeletionOrder { get; set; }
    }
}
