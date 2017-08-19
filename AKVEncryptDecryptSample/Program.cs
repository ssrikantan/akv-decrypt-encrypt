using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AKVEncryptDecryptSample
{
    class Program
    {
        static void Main(string[] args)
        {
            Receiver rec = new Receiver();
            rec.DownloadCertificate();
            //rec.EncryptDecrypt();
            Console.ReadLine();
        }
    }
}
