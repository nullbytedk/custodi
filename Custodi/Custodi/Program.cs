using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;

namespace Custodi {
    class Program {
        static void Main(string[] args) {

            RSA rsa = new RSA(2048);
            string key = rsa.GetPublicKey();
            string pkey = rsa.GetPrivateKey();

            try {
                var cipher = rsa.RSAEncrypt<string>("SecretKey", key);
                var plain = rsa.RSADecrypt<string>(cipher, pkey);
                Console.WriteLine(plain);
            }catch(InvalidCastException e) {
                Console.Error.WriteLine("The specified variable type is not supported - only string (base64 encoded) or byte[] is supported.");
            }
            
            Console.ReadLine();
        }

        


    }
}
