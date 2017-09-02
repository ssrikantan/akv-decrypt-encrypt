using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Net.Security;


namespace AKVEncryptDecryptSample
{
    /// <summary>
    /// Sender mimics an application that uses a X509 Certificate to encrypt the data before sending it to a 
    /// receiving application in Azure. This certificate contains the Public Key for the corresponding Private Key 
    /// residing in Azure Key Vault. It is used to encrypt the payload.
    /// The X509 Certificate in this sample resides on the User's certificate Store on the local machine
    /// This client program performs the encrypt operations locally (as opposed to using AKV APIs to do the same)
    /// </summary>
    class Sender
    {
       
        public byte[] Encrypt()
        {
            X509Store store = new X509Store(StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection storeCollection = store.Certificates;
            X509Certificate2 cert = null;
            foreach (X509Certificate2 c in storeCollection)
            {
                //ToDo: search string hardcoded for simplicity - to be changed as appropriate or parameterised
                if (c.Subject.Contains("demohsm.corpmobile.in"))  
                {
                    cert = c;
                    break;
                }
            }
            if (cert == null)
            {
                Console.WriteLine("Unable to locate the right Certificate ..");
                return null;
            }
            store.Close();
            byte[] plainText = GetPlainText();  // sample data to encrypt

            //This is outdated now - will work with .NET Framework 4.5. But does not support OaepSHA256
            //RSACryptoServiceProvider rsa = (RSACryptoServiceProvider)cert.PublicKey.Key;
            //byte[] encryptedData = rsa.Encrypt(plainText, true);
            
            // This requires .NET Framework 4.6.1 - RSACng Type
            byte[] encryptedData = cert.GetRSAPublicKey().Encrypt(plainText, RSAEncryptionPadding.OaepSHA256);

           
            return encryptedData;
        }

        private byte[] GetPlainText()
        {
            string text = File.ReadAllText("plainText.txt");
            return System.Text.Encoding.UTF8.GetBytes(text);
        }
      
    }
}
