#define NETFX20

using System;
using System.IO;
using System.Security.Cryptography;

namespace CryptographyDemo
{
    internal sealed class RsaAesHelper : IDisposable
    {
        #region " Instance "
        private static RsaAesHelper _instance;
        internal static RsaAesHelper Instance
        {
            get { return (_instance = _instance ?? new RsaAesHelper()); }
            set { _instance = value; }
        }
        #endregion

        #region " Consts "
        /// <summary>
        /// Benzersiz bir GUID giriniz.
        /// Her program için değiştirmeniz daha güvenli hâle getirecektir.
        /// </summary>
        private const string Id = "153102F4-1CE2-4EAE-B648-4A1C0088A785";

        /// <summary>
        /// RSA AYARLARI
        /// </summary>
        private const bool RsaPersistKeyInCsp = false;
        private const bool RsaOptimalAsymmetricEncryptionPadding = true;

        /// <summary>
        /// AES AYARLARI
        /// </summary>
        private const int AesKeySize = 256;
        private const int AesBlockSize = 128;
        private const CipherMode AesMode = CipherMode.CBC;
        private const PaddingMode AesPadding = PaddingMode.ISO10126;
        #endregion

        #region " Private  "
        private readonly RSACryptoServiceProvider _rsa;
        #endregion

        #region " Constructor "
        internal RsaAesHelper(int keySizeRsa = 1024)
        {
            if (!IsKeySizeRSADogrulama(keySizeRsa))
                throw new ArgumentException("KeySize Unverified", "keySizeRsa");

            _rsa = new RSACryptoServiceProvider(keySizeRsa) {PersistKeyInCsp = RsaPersistKeyInCsp};
        }

        internal RsaAesHelper(string rsaKeyContainerName, int keySizeRsa = 1024)
        {
            if (!IsKeySizeRSADogrulama(keySizeRsa))
                throw new ArgumentException("RSA KeySize unverified", "keySizeRsa");

            CspParameters csp = new CspParameters {KeyContainerName = rsaKeyContainerName};
            _rsa = new RSACryptoServiceProvider(keySizeRsa, csp) {PersistKeyInCsp = RsaPersistKeyInCsp};
        }

        #endregion

        #region " Hibrit "
        /// <summary>
        /// RSA ve AES Karışımı Hibrit Kriptografi
        /// </summary>
        /// <param name="veri">Byte[] değerinden şifrelenecek veri</param>
        /// <returns>Kriptolanmış veriyi döndürür</returns>
        internal byte[] SifreleHibrit(byte[] veri)
        {
            if (veri == null || veri.Length == 0)
                throw new ArgumentException("Veri is null", "veri");

            byte[] key = RastgeleByte(AesKeySize / 8);
            byte[] iv = RastgeleByte(AesBlockSize / 8);

            byte[] veriCrypt = SifreleAes(veri, key, iv);
            byte[] keyCrypt = SifreleRsa(key);
            byte[] ivCrypt = SifreleRsa(iv);
            byte[] birlestir = new byte[veriCrypt.Length + keyCrypt.Length + ivCrypt.Length];

            Buffer.BlockCopy(keyCrypt, 0, birlestir, 0, keyCrypt.Length);
            Buffer.BlockCopy(ivCrypt, 0, birlestir, keyCrypt.Length, ivCrypt.Length);
            Buffer.BlockCopy(veriCrypt, 0, birlestir, keyCrypt.Length + ivCrypt.Length, veriCrypt.Length);

            return birlestir;
        }

        /// <summary>
        /// RSA ve AES Karışımı Hibrit Kriptografi Çözümü
        /// </summary>
        /// <param name="veri">Byte[] değerinden şifrelenmiş veri</param>
        /// <returns>Kripto çözülmüş orijinal veriyi döndürür</returns>
        internal byte[] CozumleHibrit(byte[] veri)
        {
            if (veri == null || veri.Length == 0)
            {
                throw new ArgumentException("Veri is null", "veri");
            }

            byte[] keyCrypt = new byte[_rsa.KeySize >> 3];
            byte[] ivCrypt = new byte[_rsa.KeySize >> 3];
            byte[] veriCrypt = new byte[veri.Length - keyCrypt.Length - ivCrypt.Length];
            Buffer.BlockCopy(veri, 0, keyCrypt, 0, keyCrypt.Length);
            Buffer.BlockCopy(veri, keyCrypt.Length, ivCrypt, 0, ivCrypt.Length);
            Buffer.BlockCopy(veri, keyCrypt.Length + ivCrypt.Length, veriCrypt, 0, veriCrypt.Length);

            byte[] key = CozumleRsa(keyCrypt);
            byte[] iv = CozumleRsa(ivCrypt);

            return CozumleAes(veriCrypt, key, iv);
        }
        #endregion

        #region " RSA "

        /// <summary>
        /// RSA Şifreleme
        /// </summary>
        /// <param name="veri">RSA ile şifrelenecek veri</param>
        /// <returns>RSA ile şifrelenmiş veriyi döndürür</returns>
        internal byte[] SifreleRsa(byte[] veri)
        {
            return _rsa.Encrypt(veri, RsaOptimalAsymmetricEncryptionPadding);
        }

        /// <summary>
        /// RSA Şifrelenmiş veriyi çözümleme
        /// </summary>
        /// <param name="sifreliVeri">RSA ile şifrelenmiş veri</param>
        /// <returns>Orijinal veriyi döndürür</returns>
        internal byte[] CozumleRsa(byte[] sifreliVeri)
        {
            return _rsa.Decrypt(sifreliVeri, RsaOptimalAsymmetricEncryptionPadding);
        }

        /// <summary>
        /// RSA Private veya Public kodu
        /// </summary>
        /// <param name="privateKodOlsunMu">Private kod dahil edilsin mi?</param>
        /// <returns>RSA Private veya Public kodunu döndürür</returns>
        internal string ToXmlString(bool privateKodOlsunMu)
        {
            return _rsa.ToXmlString(privateKodOlsunMu);
        }

        /// <summary>
        /// RSA Private veya Public kodu
        /// </summary>
        /// <param name="xml">RSA Private veya Public kodu</param>
        internal void FromXmlString(string xml)
        {
            _rsa.FromXmlString(xml);
        }

        /// <summary> 
        /// RSA Şifrelenecek maksimum veri uzunluğunu belirtir
        /// </summary>       
        /// <param name="keySize"/>RSA Key Size
        /// <returns>İzin verilen maksimum veri uzunluğu</returns> 
        private int MaxVeriUzunluguRsa(int keySize)
        {
            return ((keySize - 384) / 8) + 7;
        }

        /// <summary> 
        /// RSA Key Size Doğrulaması
        /// </summary>       
        /// <param name="keySize"/>RSA Key Size
        /// <returns>Doğru ise true, aksi durumda false</returns> 
        private bool IsKeySizeRSADogrulama(int keySize)
        {
            return keySize >= 384 &&
                   keySize <= 16384 &&
                   keySize % 8 == 0;
        }
        #endregion

        #region " AES "

        /// <summary>
        /// AES Rijndael ile Şifreleme
        /// </summary>
        /// <param name="veri">AES ile şifrelenecek veri</param>
        /// <param name="key">Anahtar</param>
        /// <param name="iv">Initialization vector (Başlatma Vektörü)</param>
        /// <returns>AES ile şifrelenmiş veriyi döndürür</returns>
        internal static byte[] SifreleAes(byte[] veri, byte[] key, byte[] iv)
        {
            byte[] cikti;
            using (MemoryStream ms = new MemoryStream())
            using (Rijndael aes = Rijndael.Create())
            {
                aes.BlockSize = AesBlockSize;
                aes.KeySize = AesKeySize;
                aes.Mode = AesMode;
                aes.Padding = AesPadding;
                aes.Key = key;  // GetBytes(aes.KeySize / 8)
                aes.IV = iv;    // GetBytes(aes.BlockSize / 8)

                using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(veri, 0, veri.Length);
                    cs.FlushFinalBlock();
                }
                cikti = ms.ToArray();
            }
            return cikti;
        }

        /// <summary>
        /// AES Rijndael ile şifrelenmiş veriyi çözümleme
        /// </summary>
        /// <param name="sifreliVeri">Şifrelenmiş veri</param>
        /// <param name="key">Anahtar</param>
        /// <param name="iv">Initialization vector (Başlatma Vektörü)</param>
        /// <returns>Orijinal veriyi döndürür</returns>
        internal static byte[] CozumleAes(byte[] sifreliVeri, byte[] key, byte[] iv)
        {
            byte[] cikti;
            using (MemoryStream ms = new MemoryStream())
            using (Rijndael aes = Rijndael.Create())
            {
                aes.BlockSize = AesBlockSize;
                aes.KeySize = AesKeySize;
                aes.Mode = AesMode;
                aes.Padding = AesPadding;
                aes.Key = key;  // GetBytes(aes.KeySize / 8)
                aes.IV = iv;    // GetBytes(aes.BlockSize / 8)

                using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(sifreliVeri, 0, sifreliVeri.Length);
                    cs.FlushFinalBlock();
                }
                cikti = ms.ToArray();
            }
            return cikti;
        }

        #endregion

        #region " Metot "
        private byte[] RastgeleByte(int uzunluk)
        {
            byte[] cikti;
#if (NETFX20 || NETFX30 || NETFX35)
            RNGCryptoServiceProvider rastgeleSayiOlustur = new RNGCryptoServiceProvider();
#else
            using (RNGCryptoServiceProvider rastgeleSayiOlustur = new RNGCryptoServiceProvider())
#endif
            {
                cikti = new byte[uzunluk];
                rastgeleSayiOlustur.GetBytes(cikti);
            }
            return cikti;
        }

        public void Dispose()
        {

#if (NETFX20 || NETFX30 || NETFX35)
#else
            rsa.Dispose();
#endif
        }

        #endregion

    }
}