Working with Azure Key Vault Certificates for secure exchange of data  

Azure Key Vault (AKV) provides REST APIs that Applications could invoke to perform cryptographic operations like Encryption, Decryption signing and verifying signatures. For scenarios where integrated applications are deployed across Data Centers or geographies, it would be optimal to perform operations like encryption, locally, instead of making a REST API Call on Azure Key Vault. Covered here is a sample Application that uses a X509 Certificate on a local machine to encrypt the data, which is then decrypted using the AKV APIs.

Use the code sample here in the context of the Blog article here - https://blogs.msdn.microsoft.com/srikantan/2017/08/19/working-with-azure-key-vault-certificates-for-secure-exchange-of-data/

