using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace ArtisanCode.SimpleAesEncryption
{

    public abstract class RijndaelMessageHandler
    {
        public const string CYPHER_TEXT_IV_SEPARATOR = "??";

        protected string _configurationSectionName = "MessageEncryption";

        public RijndaelMessageHandler(SimpleAesEncryptionConfiguration config)
        {
            Configuration = config ?? throw new ArgumentNullException(nameof(config));
        }

        public SimpleAesEncryptionConfiguration Configuration { get; }

        public virtual void ConfigureCryptoContainer(RijndaelManaged cryptoContainer)
        {
            if (Configuration == null)
            {
                throw new ArgumentNullException(nameof(Configuration), "The whole encryption configuration is null.");
            }

            if (Configuration.EncryptionKey == null)
            {
                throw new ArgumentException(nameof(Configuration), "The encryption key configuration is null.");
            }

            if (string.IsNullOrWhiteSpace(Configuration.EncryptionKey.Key))
            {
                throw new CryptographicException("Encryption key is missing.");
            }

            if (!cryptoContainer.LegalKeySizes.Any(x => (x.MinSize <= Configuration.EncryptionKey.KeySize) && (Configuration.EncryptionKey.KeySize <= x.MaxSize)))
            {
                throw new CryptographicException("Invalid Key Size specified. The recommended value is: 256");
            }

            byte[] key = Convert.FromBase64String(Configuration.EncryptionKey.Key);

            // Check that the key length is equal to config.KeySize / 8
            // e.g. 256/8 == 32 bytes expected for the key
            if (key.Length != (Configuration.EncryptionKey.KeySize / 8))
            {
                throw new CryptographicException("Encryption key is the wrong length. Please ensure that it is *EXACTLY* " + Configuration.EncryptionKey.KeySize + " bits long");
            }

            cryptoContainer.Mode = Configuration.CipherMode;
            cryptoContainer.Padding = Configuration.Padding;
            cryptoContainer.KeySize = Configuration.EncryptionKey.KeySize;
            cryptoContainer.Key = key;

            // Generate a new Unique IV for this container and transaction (can be overridden later to decrypt messages where the IV is known)
            cryptoContainer.GenerateIV();
        }
    }
}
