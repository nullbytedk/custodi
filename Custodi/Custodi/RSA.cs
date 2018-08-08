using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Custodi {
    class RSA {
        private RSACryptoServiceProvider csp;
        public readonly string PublicKey;
        public readonly string PrivateKey;

        public RSA(int keySize) {
            csp = new RSACryptoServiceProvider(keySize);
            this.PublicKey = csp.ToXmlString(false);
            this.PrivateKey = csp.ToXmlString(true);
        }

        public string GetPublicKey() {
            return this.PublicKey; 
        }

        public string GetPrivateKey() {
            return this.PrivateKey;
        }

        private byte[] Encrypt(string plainText, string publicKey) {
            csp.FromXmlString(publicKey);
            var bytesPlainText = System.Text.Encoding.Unicode.GetBytes(plainText);
            var bytesCipherText = csp.Encrypt(bytesPlainText, false);
            return bytesCipherText;
        }

        private string Decrypt(byte[] cipherText, string privateKey) {
            csp.FromXmlString(privateKey);
            var bytesPlainTextData = csp.Decrypt(cipherText, false);
            var plainTextData = System.Text.Encoding.Unicode.GetString(bytesPlainTextData);
            return plainTextData;

        }

        public string RSADecrypt<T>(T cipherText, string privateKey) {
            Type itemType = cipherText.GetType();
            if (itemType == typeof(string)) {
                try {
                    string cipher = (string)Convert.ChangeType(cipherText, typeof(string));
                    var bytesCipherText = Convert.FromBase64String(cipher);
                    var plainTextData = Decrypt(bytesCipherText, privateKey);
                    return plainTextData;
                } catch(Exception e) {
                    Console.Error.WriteLine(e.Message);
                    throw new InvalidCastException();
                }
            } else if (itemType == typeof(byte[])) {
                try {
                    byte[] bytesCipherText = (byte[])Convert.ChangeType(cipherText, typeof(byte[]));
                    var plainTextData = Decrypt(bytesCipherText, privateKey);
                    return plainTextData;
                } catch(Exception e) {
                    Console.Error.WriteLine(e.Message);
                    throw new InvalidCastException();
                }
                
            } else {
                throw new InvalidCastException();
            }
        }

        public T RSAEncrypt<T>(string plainText, string publicKey) {
            var cipherText = Encrypt(plainText, publicKey);
            Type itemType = typeof(T);
            if (itemType == typeof(string)) {
                return (T)Convert.ChangeType(Convert.ToBase64String(cipherText), typeof(T));
            }else if (itemType == typeof(byte[])) {
                return (T)Convert.ChangeType(cipherText, typeof(T));
            } else {
                throw new InvalidCastException();
            }
        }

    





        public string GetPubblicKey() {
            //and the public key ...
            //var pubKey = csp.ExportParameters(false);
            //pubKey.
            //return pubKey;


            string publicKey = csp.ToXmlString(false);
            string privateKey = csp.ToXmlString(true);
            //csp = new RSACryptoServiceProvider();
            csp.FromXmlString(publicKey);
            //we need some data to encrypt
            var orgPlainTextData = "SuperSecretKey";

            //for encryption, always handle bytes...
            var bytesPlainTextData = System.Text.Encoding.Unicode.GetBytes(orgPlainTextData);

            //apply pkcs#1.5 padding and encrypt our data 
            var bytesCypherText = csp.Encrypt(bytesPlainTextData, false);

            //we might want a string representation of our cypher text... base64 will do
            var cypherText = Convert.ToBase64String(bytesCypherText);
            Console.WriteLine(cypherText);




            bytesCypherText = Convert.FromBase64String(cypherText);

            //we want to decrypt, therefore we need a csp and load our private key
            //csp = new RSACryptoServiceProvider();
            csp.FromXmlString(privateKey);

            //decrypt and strip pkcs#1.5 padding
            bytesPlainTextData = csp.Decrypt(bytesCypherText, false);

            //get our original plainText back...
            var plainTextData = System.Text.Encoding.Unicode.GetString(bytesPlainTextData);

            Console.WriteLine(String.Format("Plain: {0}, Encrypt: {1}, Decrypt: {2}", orgPlainTextData, cypherText, plainTextData));
















            // var serverRSA = new RSACryptoServiceProvider(new CspParameters() {
            //     KeyContainerName = "fullKeyContainer"
            // }
            // );

            // var clientRSA = new RSACryptoServiceProvider(new CspParameters() {
            //     KeyContainerName = "publicKeyContainer"
            // }
            //);

            // clientRSA.ImportCspBlob(serverRSA.ExportCspBlob(false));

            // string clientPublicKey = clientRSA.ToXmlString(false);
            // string serverPublicKey = serverRSA.ToXmlString(false);
            // Console.WriteLine(clientPublicKey);
            //Console.WriteLine(serverPublicKey);
            //Console.WriteLine(clientPublicKey.Equals(serverPublicKey));

            return publicKey;
        }
    }
}
