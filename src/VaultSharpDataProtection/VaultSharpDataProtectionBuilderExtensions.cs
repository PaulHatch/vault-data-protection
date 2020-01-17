using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.DependencyInjection;
using VaultDataProtection;
using VaultSharp;
using VaultSharp.V1.AuthMethods.Token;

namespace Microsoft.AspNetCore.DataProtection
{
    /// <summary>
    /// Provides registration methods for VaultSharp data protection key repository.
    /// </summary>
    public static class VaultSharpDataProtectionBuilderExtensions
    {
        const string _defaultPath = "data-protection-keys";
        const string _defaultMountPoint = "kv";

        /// <summary>
        /// Configures the data protection system to persist keys to Vault
        /// using the default path and mount point.
        /// </summary>
        /// <param name="builder">The builder instance to modify.</param>
        /// <param name="vaultClient">The client to use.</param>
        /// <returns>
        /// A reference to the <see cref="IDataProtectionBuilder" />.
        /// </returns>
        public static IDataProtectionBuilder PersistKeysToVault(
            this IDataProtectionBuilder builder,
            IVaultClient vaultClient) => builder.PersistKeysToVault(vaultClient, null, null);

        /// <summary>
        /// Configures the data protection system to persist keys to Vault.
        /// </summary>
        /// <param name="builder">The builder instance to modify.</param>
        /// <param name="vaultClient">The client to use.</param>
        /// <param name="path">The path to store keys to.</param>
        /// <param name="mountPoint">The Vault key/value mount point.</param>
        /// <returns>
        /// A reference to the <see cref="IDataProtectionBuilder" />.
        /// </returns>
        public static IDataProtectionBuilder PersistKeysToVault(
            this IDataProtectionBuilder builder,
            IVaultClient vaultClient,
            string path,
            string mountPoint)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            if (vaultClient == null)
            {
                throw new ArgumentNullException(nameof(vaultClient));
            }

            builder.Services.Configure<KeyManagementOptions>(o =>
            {
                o.XmlRepository = new VaultSharpXmlRepository(vaultClient, path ?? _defaultPath, mountPoint ?? _defaultMountPoint);
            });

            return builder;
        }

        /// <summary>
        /// Configures the data protection system to persist keys to Vault
        /// using the default path and mount point.
        /// </summary>
        /// <param name="builder">The builder instance to modify.</param>
        /// <param name="clientBuilder">The client builder.</param>
        /// <returns>
        /// A reference to the <see cref="IDataProtectionBuilder" />.
        /// </returns>
        public static IDataProtectionBuilder PersistKeysToVault(
            this IDataProtectionBuilder builder,
            Func<IVaultClient> clientBuilder) => builder.PersistKeysToVault(clientBuilder, null, null);


        /// <summary>
        /// Configures the data protection system to persist keys to Vault.
        /// </summary>
        /// <param name="builder">The builder instance to modify.</param>
        /// <param name="clientBuilder">The client builder.</param>
        /// <param name="path">The path to store keys to.</param>
        /// <param name="mountPoint">The Vault key/value mount point.</param>
        /// <returns>
        /// A reference to the <see cref="IDataProtectionBuilder" />.
        /// </returns>
        public static IDataProtectionBuilder PersistKeysToVault(
            this IDataProtectionBuilder builder,
            Func<IVaultClient> clientBuilder,
            string path,
            string mountPoint)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            if (clientBuilder == null)
            {
                throw new ArgumentNullException(nameof(clientBuilder));
            }

            return PersistKeysToVault(builder, clientBuilder(), path, mountPoint);
        }

        /// <summary>
        /// Configures the data protection system to persist keys to Vault.
        /// </summary>
        /// <param name="builder">The builder instance to modify.</param>
        /// <param name="vaultUri">The Vault URI.</param>
        /// <param name="token">The Vault access token.</param>
        /// <param name="path">The path to store keys to.</param>
        /// <param name="mountPoint">The Vault key/value mount point.</param>
        /// <returns>
        /// A reference to the <see cref="IDataProtectionBuilder" />.
        /// </returns>
        public static IDataProtectionBuilder PersistKeysToVault(
            this IDataProtectionBuilder builder,
            Uri vaultUri,
            string token,
            string path,
            string mountPoint)
        {
            var client = new VaultClient(new VaultClientSettings(vaultUri.ToString(), new TokenAuthMethodInfo(token)));
            return builder.PersistKeysToVault(client, path, mountPoint);
        }

        /// <summary>
        /// Configures the data protection system to persist keys to Vault
        /// using the default path and mount point.
        /// </summary>
        /// <param name="builder">The builder instance to modify.</param>
        /// <param name="vaultUri">The Vault URI.</param>
        /// <param name="token">The Vault access token.</param>
        /// <returns>
        /// A reference to the <see cref="IDataProtectionBuilder" />.
        /// </returns>
        public static IDataProtectionBuilder PersistKeysToVault(
            this IDataProtectionBuilder builder,
            Uri vaultUri,
            string token) => builder.PersistKeysToVault(vaultUri, token, null, null);
    }
}
