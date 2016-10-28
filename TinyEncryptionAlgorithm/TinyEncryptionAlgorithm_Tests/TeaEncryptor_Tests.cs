using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Menelabs.TinyEncryptionAlgorithm.Tests
{
    [TestClass]
    public class TeaEncryptor_Tests
    {
        [TestMethod]
        [DataRow("1")]
        [DataRow("0")]
        [DataRow("p")]
        [DataRow("απόψε την κιθάρα μου τη στόλισα κορδέλες")]
        [DataRow("pk")]
        [DataRow("pksdfhkjhfkashdkhkahdfklahfd")]
        [DataRow("pksdfh%kjhfkashdkhk^*1@!@##$ahdfklahfd")]
        [DataRow("tttt2323")]
        public void Encrypt_Decrypt_TheSame(string text)
        {
            var encryptor = ProvideTinyEncryptor();

            var cypherText = encryptor.Encrypt(text);
            var decrypted = encryptor.Decrypt(cypherText);

            Assert.AreEqual(text, decrypted);
        }

        [TestMethod]
        [DataRow("1")]
        [DataRow("1234567890123456")]
        [DataRow("123456789012345699999999")]
        [DataRow("1234")]
        public void Constructor_KeyLength_EncryptDecryptNormaly(string key)
        {
            var encryptor = ProvideTinyEncryptor(key);
            var textToEncrypt = "DummyText";

            var cypherText = encryptor.Encrypt(textToEncrypt);
            var decrypted = encryptor.Decrypt(cypherText);

            Assert.AreEqual(textToEncrypt, decrypted);
        }

        
        private TeaEncryptor ProvideTinyEncryptor(string key = null)
        {
            key = key == null ? "TestKeyForEncryption" : key;
            return new TeaEncryptor(key);
        }
    }
}
