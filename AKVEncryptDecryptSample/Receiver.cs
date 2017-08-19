using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Azure.KeyVault.WebKey;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Configuration;


namespace AKVEncryptDecryptSample
{
    /// <summary>
    /// This Program decrypts a payload by calling the Azure Key Vault APIs
    /// In the example here, the private key is stored in a HSM in AKV, and the public key for this certificate
    /// is shared with the 'Sender' program (Sender.cs in this example)
    /// 
    /// This code reuses the sample code from the AKV Documentation https://www.microsoft.com/en-us/download/details.aspx?id=45343
    /// Running the setup script in the sample above, successfully, is a pre-requisite for this Program. After that,
    ///  1. Update the values of mandatory variables in GetAppConfigSettings.ps1
    ///  2. Launch the Microsoft Azure PowerShell window
    ///  3. Run the GetAppConfigSettings.ps1 script within the Microsoft Azure PowerShell window
    ///  4. Copy the results of the script into the AKVEncryptDecryptSample\App.config file
    /// </summary>
    public class Receiver
    {
        private KeyVaultClient keyVaultClient;

        // Ensure the Values are set in the app.config before running this program
        private static string clientId;
        private static string vaultAddress;
        private static string cerificateThumbprint;
        private static string certificateName;
        private static string Keyidentifier;


        public Receiver()
        {
            vaultAddress = ConfigurationManager.AppSettings["VaultUrl"];
            clientId = ConfigurationManager.AppSettings["AuthClientId"];
            certificateName = ConfigurationManager.AppSettings["AKVCertificateName"];
            cerificateThumbprint = ConfigurationManager.AppSettings["AuthCertThumbprint"];
            Keyidentifier = ConfigurationManager.AppSettings["PrivateKeyUri"];

            // create access token to execute AKV APIs
            var certificate = FindCertificateByThumbprint(cerificateThumbprint);
            var assertionCert = new ClientAssertionCertificate(clientId, certificate);
            keyVaultClient = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(
                 (authority, resource, scope) => GetAccessToken(authority, resource, scope, assertionCert)));
        }

      
        public void EncryptDecrypt()
        {
           //DownloadCertificate(); // Needs to be called only once to get the public portion of the certificate in AKV
           byte[] encryptedData= new Sender().Encrypt();
           Decrypt(encryptedData);
        }


        /// <summary>
        /// Retrieves the public portion of the Certificate in AKV and saves that as a certificate on the
        /// local machine. This certificate would then be used in the Sender.cs to encrypt the data locally.
        /// Note: This is meant only for development time testing, and not for Production. 
        /// In practice, this X509 Certificate would be signed and issued by a CA, which could then be used for
        /// encryption. For simplicity here, a Self signed certificate generated in Key Vault is downloaded and used.
        /// 
        /// </summary>
        /// <returns></returns>
        public void DownloadCertificate()
        {
            X509Certificate2 cert = null;
            CertificateBundle bundle = null;
            //byte[] encryptedData = null;
            try
            {
                bundle = Task.Run(() => keyVaultClient.GetCertificateAsync(vaultAddress, certificateName)).ConfigureAwait(false).GetAwaiter().GetResult();
                cert = new X509Certificate2(bundle.Cer);
                //save the certificate to the local machine
                File.WriteAllBytes("programcert.crt", bundle.Cer);

                // Instead of downloading the certificate to the computer, it could also be directly used
                // for encryption locally. Uncomment the following lines if the Certificate should be used directly
                //var crypto = cert.PublicKey.Key;
                //RSACryptoServiceProvider rsa = (RSACryptoServiceProvider)cert.PublicKey.Key;
                //byte[] plainText = GetPlainText();
                //encryptedData = rsa.Encrypt(plainText, true);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception downloading the certificate " + ex.StackTrace);
            }
            //return encryptedData;
        }

        // decrypts the data received by calling the AKV API
        private void Decrypt(byte[] cipherText)
        {
            KeyOperationResult operationResult;
            var algorithm = JsonWebKeyEncryptionAlgorithm.RSAOAEP;
            try
            {
                operationResult = Task.Run(() => keyVaultClient.DecryptAsync(Keyidentifier, algorithm, cipherText)).ConfigureAwait(false).GetAwaiter().GetResult();
                Console.Out.WriteLine(string.Format("The decrypted text is: {0}", Encoding.UTF8.GetString(operationResult.Result)));

            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception during decryption " + ex.StackTrace);
            }
        }


        #region code from AKV Documentation
        //Code retained from the AKV Documentation https://www.microsoft.com/en-us/download/details.aspx?id=45343 as is
        // just for reference

        /// <summary>
        /// This is for the application to authenticate with AKV through Azure AD to be able to carry out the Decrypt and 
        /// verify operations on AKV. Authentication is done using the certificate stored locally on this computer
        /// which is retrieved in this method, based on its thumbprint
        /// </summary>
        /// <param name="certificateThumbprint"></param>
        /// <returns></returns>
        private static X509Certificate2 FindCertificateByThumbprint(string certificateThumbprint)
        {
            if (certificateThumbprint == null)
                throw new System.ArgumentNullException("certificateThumbprint");

            foreach (StoreLocation storeLocation in (StoreLocation[])
                Enum.GetValues(typeof(StoreLocation)))
            {
                foreach (StoreName storeName in (StoreName[])
                    Enum.GetValues(typeof(StoreName)))
                {
                    X509Store store = new X509Store(storeName, storeLocation);

                    store.Open(OpenFlags.ReadOnly);
                    X509Certificate2Collection col = store.Certificates.Find(X509FindType.FindByThumbprint, certificateThumbprint, false); // Don't validate certs, since the test root isn't installed.
                    if (col != null && col.Count != 0)
                    {
                        foreach (X509Certificate2 cert in col)
                        {
                            if (cert.HasPrivateKey)
                            {
                                store.Close();
                                return cert;
                            }
                        }
                    }
                }
            }
            throw new System.Exception(
                    string.Format("Could not find the certificate with thumbprint {0} in any certificate store.",
                    certificateThumbprint));
        }
        private static async Task<string> GetAccessToken(string authority, string resource, string scope, ClientAssertionCertificate assertionCert)
        {
            var context = new AuthenticationContext(authority, TokenCache.DefaultShared);
            var result = await context.AcquireTokenAsync(resource, assertionCert).ConfigureAwait(false);
            return result.AccessToken;
        }
        private byte[] GetPlainText()
        {
            string text = File.ReadAllText("plainText.txt");
            return System.Text.Encoding.UTF8.GetBytes(text);
        }
#endregion
    }
}
