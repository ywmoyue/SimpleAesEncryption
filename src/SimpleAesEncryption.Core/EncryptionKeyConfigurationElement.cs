using System;
using System.Collections.Generic;
using System.Text;

namespace ArtisanCode.SimpleAesEncryption
{
    public class EncryptionKeyConfigurationElement
    {
        public EncryptionKeyConfigurationElement()
        {
        }

        public EncryptionKeyConfigurationElement(int keySize, string key)
        {
            this.KeySize = keySize;
            this.Key = key;
        }

        public string Key { get; set; }
        public int KeySize { get; set; } = 256;
    }
}
