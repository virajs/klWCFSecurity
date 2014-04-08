using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Security;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Dispatcher;
using System.ServiceModel.Security;
using System.Text;
using System.Xml;

namespace klWCFCryptoHelper
{
    public class CryptoHelper
    {
        public static byte[] Sign(byte[] data, X509Certificate2 signingCert)
        {
            ContentInfo content = new ContentInfo(data);

            SignedCms signedMessage = new SignedCms(content);

            CmsSigner signer = new CmsSigner(signingCert);

            signedMessage.ComputeSignature(signer);

            byte[] signedBytes = signedMessage.Encode();

            return signedBytes;
        }

        public static byte[] SignDetached(byte[] data, X509Certificate2 signingCert)
        {
            ContentInfo content = new ContentInfo(data);

            SignedCms signedMessage = new SignedCms(content, true);

            CmsSigner signer = new CmsSigner(signingCert);

            signedMessage.ComputeSignature(signer);

            byte[] signedBytes = signedMessage.Encode();
            return signedBytes;
        }

        public static void ValidateCert(X509Certificate2 cert)
        {
            X509Chain chain = new X509Chain();

            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;

            chain.ChainPolicy.RevocationMode = X509RevocationMode.Online | X509RevocationMode.Offline;

            chain.ChainPolicy.UrlRetrievalTimeout = new TimeSpan(0, 0, 30);

            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

            chain.Build(cert);

            if (chain.ChainStatus.Length != 0)
                Console.WriteLine(chain.ChainStatus[0].Status);
        }

        public static X509Certificate2 FindCertificate(StoreLocation location, StoreName name, X509FindType findType, string findValue)
        {
            X509Store store = new X509Store(name, location);
            try
            {
                store.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection col = store.Certificates.Find(findType, findValue, true);

                return col[0];
            }
            finally { store.Close(); }
        }

        public static byte[] Encrypt(byte[] data, X509Certificate2 encryptingCert)
        {
            ContentInfo plainContent = new ContentInfo(data);

            EnvelopedCms encryptedData = new EnvelopedCms(plainContent);

            CmsRecipient recipient = new CmsRecipient(encryptingCert);

            encryptedData.Encrypt(recipient);

            byte[] encryptedBytes = encryptedData.Encode();

            return encryptedBytes;
        }

        public static bool VerifyDetached(byte[] data, byte[] signature)
        {
            ContentInfo content = new ContentInfo(data);

            SignedCms signedMessage = new SignedCms(content, true);

            signedMessage.Decode(signature);

            try
            {
                signedMessage.CheckSignature(false);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public static byte[] VerifyAndRemoveSignature(byte[] data)
        {
            SignedCms signedMessage = new SignedCms();

            signedMessage.Decode(data);

            signedMessage.CheckSignature(false);

            foreach (SignerInfo signer in signedMessage.SignerInfos)
            {
                Console.WriteLine("Subject: {0}", signer.Certificate.Subject);
            }

            return signedMessage.ContentInfo.Content;
        }
    }

    public class CertificateManager
    {
        public static string GetMacAddress()
        {
            IPGlobalProperties.GetIPGlobalProperties();
            NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();
            //Console.WriteLine("Interface information for {0}.{1}     ",computerProperties.HostName, computerProperties.DomainName);
            var myMac = "";
            foreach (var adapter in nics)
            {
                if (adapter != null)
                {
                    adapter.GetIPProperties();
                    //Console.WriteLine(adapter.Description);
                    //Console.WriteLine(String.Empty.PadLeft(adapter.Description.Length, '='));
                    //Console.WriteLine("  Interface type .......................... : {0}", adapter.NetworkInterfaceType);
                    //Console.WriteLine("  Physical Address ........................ : {0}", adapter.GetPhysicalAddress().ToString());
                    Console.WriteLine("  MacAddress .............................. : {0}", adapter.Id);
                    //Console.WriteLine("  Is receive only.......................... : {0}", adapter.IsReceiveOnly);
                    //Console.WriteLine("  Multicast................................ : {0}", adapter.SupportsMulticast);
                    //Console.WriteLine();

                    myMac = adapter.Id;
                }
            }
            return myMac;

        }

        public static SecureString GetSecureStringFromConsole()
        {
            var password = new SecureString();

            Console.Write("Enter Password: ");
            while (true)
            {
                ConsoleKeyInfo cki = Console.ReadKey(true);

                if (cki.Key == ConsoleKey.Enter) break;
                if (cki.Key == ConsoleKey.Escape)
                {
                    password.Dispose();
                    return null;
                }
                if (cki.Key == ConsoleKey.Backspace)
                {
                    if (password.Length != 0)
                        password.RemoveAt(password.Length - 1);
                }
                else password.AppendChar(cki.KeyChar);
            }

            return password;
        }

        public static void InstallCertificates()
        {
            LicenseKeyHelper.CheckLicenseKey();

            SecureString mySs = GetSecureStringFromConsole();

            var klBaseCert = new X509Certificate2("klBase.pfx", mySs);
            var klClientCert = new X509Certificate2("klClient.pfx", mySs);
            var klServerCert = new X509Certificate2("klServer.pfx", mySs);

            var store = new X509Store("TRUST", StoreLocation.LocalMachine);
            try
            {
                store.Open(OpenFlags.ReadWrite);
                store.Add(klBaseCert);
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);


            }
            finally
            {
                store.Close();
            }

            store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            try
            {
                store.Open(OpenFlags.ReadWrite);
                store.Add(klClientCert);
                store.Add(klServerCert);
            }
            finally
            {
                store.Close();
            }

            store = new X509Store(StoreName.TrustedPeople, StoreLocation.LocalMachine);
            try
            {
                store.Open(OpenFlags.ReadWrite);
                store.Add(klClientCert);
                store.Add(klServerCert);
            }
            finally
            {
                store.Close();
            }


            ValidateCert(klBaseCert);
            ValidateCert(klServerCert);
            ValidateCert(klClientCert);

            RevokeCertificate(klBaseCert);
            RevokeCertificate(klClientCert);
            RevokeCertificate(klServerCert);

        }

        public static void ValidateCert(X509Certificate2 cert)
        {
            var chain = new X509Chain();

            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;

            chain.ChainPolicy.RevocationMode = X509RevocationMode.Online; //| X509RevocationMode.Offline;

            chain.ChainPolicy.UrlRetrievalTimeout = new TimeSpan(0, 0, 30);

            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

            chain.Build(cert);

            if (chain.ChainStatus.Length != 0)
                Console.WriteLine(chain.ChainStatus[0].Status);

            GrantKeyAccess.GetKey(cert);
            GrantKeyAccess.AddAccessToCertificate(cert, "kl\\bruce.campbell");

        }

        public static void RevokeCertificate(X509Certificate2 cert)
        {
            //CERTADMINLib.CCertAdminClass certAdmin = new
            //CERTADMINLib.CCertAdminClass();
            //string strConfig =
            //configurationBase.GetConfigParamValueByParamName("CAName");
            //string strSert = X509Cert.GetSerialNumberString();
            //issueDate = X509Cert.NotBefore;
            ////PrintParameters(strConfig,strSert);
            //certAdmin.RevokeCertificate(strConfig, strSert, 0,DateTime.UtcNow.Date);

            string[] CRL = X509Certificate2Extensions.GetCrlDistributionPoints(cert);

        }

        public static class LicenseKeyHelper
        {
            public static void CheckLicenseKey()
            {
                var mac = GetMacAddress();

                var klLicenseCert = new X509Certificate2("klLicenseKeyGen.cer");

                var myMac = new byte[mac.Length];
                for (int i = 0; i < mac.Length; i++)
                    myMac[i] = (byte)mac[i];

                byte[] mySignedMacPrivateKey = SignMacWithPrivateKey(myMac);

                byte[] myDecodedMacPrivate = CryptoHelper.VerifyAndRemoveSignature(mySignedMacPrivateKey);

                for (int i = 0; i < myDecodedMacPrivate.Length; i++)
                {
                    if (myDecodedMacPrivate[i] != myMac[i])
                    {
                        throw new Exception("kl License Key Invalid");
                    }
                }

                var myFile = File.OpenWrite("signedMac");
                myFile.Write(mySignedMacPrivateKey, 0, mySignedMacPrivateKey.Length);
                myFile.Close();

                //delete certificates here
                var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                try
                {
                    store.Open(OpenFlags.ReadWrite);
                    store.Add(klLicenseCert);

                }
                finally
                {
                    store.Close();
                }

                store = new X509Store(StoreName.TrustedPeople, StoreLocation.LocalMachine);
                try
                {
                    store.Open(OpenFlags.ReadWrite);
                    store.Add(klLicenseCert);

                }
                finally
                {
                    store.Close();
                }
                myFile = File.OpenRead("signedMac");
                long length = myFile.Length;
                var myRead = new byte[length];
                myFile.Read(myRead, 0, (int)length);
                myFile.Close();
                byte[] myDecodedMac = CryptoHelper.VerifyAndRemoveSignature(mySignedMacPrivateKey);
            }

            public static byte[] SignMacWithPrivateKey(byte[] mac)
            {
                X509Certificate2 myCert = CryptoHelper.FindCertificate(StoreLocation.LocalMachine, StoreName.My, X509FindType.FindBySubjectDistinguishedName, "CN=klLicenseKeyGen");

                byte[] mySignedMac = CryptoHelper.Sign(mac, myCert);

                return mySignedMac;
            }
        }

        public static class X509Certificate2Extensions
        {
            public static string[] GetCrlDistributionPoints(X509Certificate2 certificate)
            {
                if (certificate == null)
                {
                    throw new ArgumentNullException("certificate");
                }
                X509Extension ext = certificate.Extensions.Cast<X509Extension>().FirstOrDefault(
                    e => e.Oid.Value == "2.5.29.31");

                if (ext == null || ext.RawData == null || ext.RawData.Length < 11)
                    return EmptyStrings;

                int prev = -2;
                var items = new List<string>();
                while (prev != -1 && ext.RawData.Length > prev + 1)
                {
                    int next = IndexOf(ext.RawData, 0x86, prev == -2 ? 8 : prev + 1);
                    if (next == -1)
                    {
                        if (prev >= 0)
                        {
                            string item = Encoding.UTF8.GetString(ext.RawData, prev + 2, ext.RawData.Length - (prev + 2));
                            items.Add(item);
                        }

                        break;
                    }

                    if (prev >= 0 && next > prev)
                    {
                        string item = Encoding.UTF8.GetString(ext.RawData, prev + 2, next - (prev + 2));
                        items.Add(item);
                    }

                    prev = next;
                }

                return items.ToArray();
            }

            static int IndexOf(byte[] instance, byte item, int start)
            {
                for (int i = start, l = instance.Length; i < l; i++)
                    if (instance[i] == item)
                        return i;

                return -1;
            }

            private static string[] EmptyStrings = new string[0];
        }

        class GrantKeyAccess
        {
            public static void GetKey(X509Certificate2 cert)
            {
                string keyfileName = GetKeyFileName(cert);
                string keyfilePath = FindKeyLocation(keyfileName);

                Console.WriteLine(keyfilePath);
                Console.WriteLine(keyfileName);

                Console.WriteLine("Press enter to continue");
                Console.ReadLine();

            }

            private static string FindKeyLocation(string keyFileName)
            {
                // check machine path first
                string machinePath = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                string machinePathFull = machinePath + @"\Microsoft\Crypto\RSA\MachineKeys";
                string[] machineFiles = Directory.GetFiles(machinePathFull, keyFileName);
                if (machineFiles.Length > 0)
                {
                    return machinePathFull;
                }

                // then user path
                string userPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                string userPathFull = userPath + @"\Microsoft\Crypto\RSA\";
                string[] userDirectories = Directory.GetDirectories(userPathFull);

                if (userDirectories.Length > 0)
                {
                    string[] userDirectoriesClone = userDirectories;
                    for (int i = 0; i < userDirectoriesClone.Length; i++)
                    {
                        string dir = userDirectoriesClone[i];
                        userDirectories = Directory.GetFiles(dir, keyFileName);
                        if (userDirectories.Length != 0)
                        {
                            return dir;
                        }
                    }
                }
                return null;
            }

            public static string GetKeyFileName(X509Certificate2 cert)
            {
                string filename = null;

                if (cert.PrivateKey != null)
                {
                    RSACryptoServiceProvider provider = cert.PrivateKey as RSACryptoServiceProvider;
                    filename = provider.CspKeyContainerInfo.UniqueKeyContainerName;
                }
                return filename;
            }

            public static void AddAccessToCertificate(X509Certificate2 cert, string user)
            {
                RSACryptoServiceProvider rsa = cert.PrivateKey as RSACryptoServiceProvider;
                if (rsa != null)
                {
                    string keyfilepath = FindKeyLocation(rsa.CspKeyContainerInfo.UniqueKeyContainerName);
                    FileInfo file = new FileInfo(keyfilepath + "\\" + rsa.CspKeyContainerInfo.UniqueKeyContainerName);
                    Console.WriteLine(file.Name);
                    FileSecurity fs = file.GetAccessControl();
                    NTAccount account = new NTAccount(user);
                    fs.AddAccessRule(new FileSystemAccessRule(account, FileSystemRights.FullControl, AccessControlType.Allow));
                    file.SetAccessControl(fs);
                }
            }
        }
    }


}