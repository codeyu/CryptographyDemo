using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptographyDemo
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                var publicKey = RsaAesHelper.Instance.ToXmlString(false);
                var privateKey = RsaAesHelper.Instance.ToXmlString(true);

                //Console.WriteLine("Public Key\t: {0}\r\n", publicKey);
                //Console.WriteLine("Private Key\t: {0}\r\n", privateKey);

                const string text = "{ board4all.biz; }";

                byte[] original = Encoding.UTF8.GetBytes(text);
                //original = System.IO.File.ReadAllBytes(System.Reflection.Assembly.GetExecutingAssembly().Location);

                byte[] encrypted = RsaAesHelper.Instance.SifreleHibrit(original);

                RsaAesHelper.Instance.FromXmlString(privateKey);
                byte[] decrypted = RsaAesHelper.Instance.CozumleHibrit(encrypted);

                string decryptedText = Encoding.UTF8.GetString(decrypted);

                Console.WriteLine("Original\t: {0}\r\n", text);
                Console.WriteLine("encrypted\t: {0}\r\n", Convert.ToBase64String(encrypted));
                Console.WriteLine("decrypted\t: {0}\r\n", decryptedText);
                Console.Write("MD5\t\t: ");

                Console.WriteLine(
                    BitConverter.ToString(System.Security.Cryptography.MD5.Create().ComputeHash(original)) ==
                    BitConverter.ToString(System.Security.Cryptography.MD5.Create().ComputeHash(decrypted))
                        ? "Verified."
                        : "Not Verified.");
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
            finally
            {
                Console.ReadKey();
            }
        }
    }
}
