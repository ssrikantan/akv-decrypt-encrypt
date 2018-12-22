## Working with Azure Key Vault Certificates for secure exchange of data  

## Abstract
Azure Key Vault (AKV) provides REST APIs that Applications could invoke to perform cryptographic operations like Encryption, Decryption signing and verifying signatures. For scenarios where integrated applications are deployed across Data Centers or geographies, it would be optimal to perform operations like encryption, locally, instead of making a REST API Call on Azure Key Vault. Covered here is a sample Application that uses a X509 Certificate on a local machine to encrypt the data, which is then decrypted using the AKV APIs.

The Certificates feature in AKV is used here. Creating a Certificate in AKV also creates a Private/public key pair in it. A Certificate Signing Request(CSR) is generated for this Certificate which is sent to a CA for signing. The resulting X509 Certificate issued by the CA can then be used in an Application to encrypt data locally. While this is the approach that could be used in Production scenarios, for simplicity here, a X509 Certificate is retrieved, using the AKV APIs instead. This contains the Public key information for the Certificate created in AKV earlier. This is saved to the local computer and then used in the Application to perform encryption locally.

The sample Visual Studio 2017 Solution file and the PowerShell scripts are avaible for download from this Repo.

To run the sample, follow these steps:
### Provision and configure Resources in Azure Key Vault
Run the GetAppConfigSettings.ps1 PowerShell script. It is located within the scripts subfolder in the Visual Studio Solution (AKVEncryptDecryptSample.Sln). Edit the variable names used in the script before execution. The following actions are performed by this script:
* Azure Key Vault created using the Premium Tier ( a pre-requisite if HSM enabled keys are a requirement)
* The sample application (the Visual Studio Solution in this article) gets registered with Azure AD and permissions provided to it to execute the Key Vault operations. A certificate is generated to authenticate the Application with Azure AD and is stored locally on the computer.
* Creation of a Certificate in AKV having its key in a HSM. Since this is for dev/testing, a self-signed certificate is created (-IssuerName Self). 

Note: In practice, a Certificate Signing Request(CSR) is generated for this Certificate from AKV, (steps documented [here](https://blogs.technet.microsoft.com/kv/2016/09/26/manage-certificates-via-azure-key-vault/), which is signed by a trusted CA, and a X509 Certificate issued. This X509 Certificate, contains the Public key information for the Certificate created in AKV, and used in the Application to encrypt the payload with, locally. 
For simplicity here, instead, a Self-signed certificate generated in Key Vault is downloaded to the local machine using the AKV API.

Explained below are some of the snippets from the PowerShell script


Create a Certificate in AKV, having a private key in HSM & non-exportable

````
$hsmcertificateName = "prohsmcert"
````
Set the flag for Keytype as RSA-HSM; it should be non-exportable. Set the IssuerName as 'Self' since this would be used only for dev testing. (It would be set to 'Unknown' if it is to be sent to a CA for signing and issuance) set the Keyusage flags as shown. Data encipherment is not enabled by default, unless specified - it is required for decryption operation
````
$manualPolicy = New-AzureKeyVaultCertificatePolicy -SubjectName "CN=demohsm.corpmobile.in,
St=Karnataka, OU=IT, O=Demo Bank, STREET=Technology Links Park, L = Bangalore,
C=IN" -ValidityInMonths 24 -IssuerName Self -KeyType "RSA-HSM" -KeyNotExportable -KeyUsage keyEncipherment,digitalSignature,dataEncipherment
Add-AzureKeyVaultCertificate -VaultName $vaultName -Name $hsmcertificateName -CertificatePolicy $manualPolicy
````
By default the key status is disabled. Need to enable it with this command

````
Set-AzureKeyVaultCertificateAttribute -VaultName $vaultName -Name $hsmcertificateName -Enable $true
$certificateOperation = Get-AzureKeyVaultCertificateOperation -VaultName $vaultName -Name $hsmcertificateName
$certificateOperation.Status
$certificate = Get-AzureKeyVaultCertificate -VaultName $vaultName -Name $hsmcertificateName
$certificate.KeyId
````
Note: KeyId contains the URI of the private Key generated for this Certificate
• Next, copy the xml settings with the resource names from the PowerShell script execution window (see below) and paste them into the app.config of the Visual Studio Solution - Name AKVEncryptDecryptSample.Sln.

````
Write-Host "Paste the following settings into the app.config file for the HelloKeyVault project:"
<add key="VaultUrl" value="' + $vault.VaultUri + '"/>
<add key="AuthClientId" value="' + $servicePrincipal.ApplicationId + '"/>
<add key="AuthCertThumbprint" value="' + $myCertThumbprint + '"/>
<add key="PrivateKeyUri" value="' + $certificate.KeyId + '"/>
<add key="AKVCertificateName" value="' + $hsmcertificateName + '"/>
Write-Host
````
### Running the Visual Studio Solution - AKVEncryptDecryptSample
* Download the Public key content for the Certificate from Azure Key Vault Service and save to local Computer
In Program.cs, run only the DownloadCertificate() Method. This calls the [GetCertificate](https://docs.microsoft.com/en-us/rest/api/keyvault/getcertificate) API of AKV to get the CER content of the Certificate bundle. An X509 Certificate file gets saved to the bin\debug\Programcert.crt.
* Install this Certificate into the Certificate Store of the Current user
* In the Sender.cs file, change the search criteria for the Subject in the Certificate downloaded above.
if (c.Subject.Contains("demohsm.corpmobile.in"))
* In Program.cs, comment the DownloadCertificate() method and run the EncryptDecrypt() Method.
The Sender.cs program reads the text in the file in the Solution, encrypts it using the X509Certificate (Programcert.crt)from the local machine. The Receiver.cs program decrypts this content inside the HSM in AKV using the Private key in it.
 
The sample code referred in this article reuses most of what is available in the Azure Key Vault, Code Sample download Link  here, including the PowerShell scripts. Incremental changes have been made to implement the scenario covered [here](https://www.microsoft.com/en-us/download/details.aspx?id=45343)


