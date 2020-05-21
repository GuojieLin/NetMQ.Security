using NetMQ.Security;
using NetMQ.Security.Extensions;
using NetMQ.Security.V0_1;
using NetMQ.Sockets;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace NetMQ.Console
{
    class RSADe
    {
        public static void Do(string content)
        {
            X509Certificate2 certificate = new X509Certificate2(
                System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "server.pfx"), "1234");
            byte[] contentBytes = content.ConvertHexToByteArray();
            byte[] masterkey = new byte[128];
            Buffer.BlockCopy(contentBytes, contentBytes.Length - 128, masterkey, 0, 128);
            var rsa = certificate.PrivateKey as RSACryptoServiceProvider;

            byte[] premasterSecret = rsa.Decrypt(masterkey, false);
            System.Console.WriteLine(BitConverter.ToString(premasterSecret, 0, premasterSecret.Length));

        }
        public static void Do2(string content)
        {
            X509Certificate2 certificate = new X509Certificate2(
                System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "server.pfx"), "1234");
            byte[] contentBytes = content.ConvertHexToByteArray2();
            byte[] masterkey = new byte[128];
            Buffer.BlockCopy(contentBytes, contentBytes.Length - 128, masterkey, 0, 128);
            var rsa = certificate.PrivateKey as RSACryptoServiceProvider;

            byte[] premasterSecret = rsa.Decrypt(masterkey, false);
            System.Console.WriteLine(BitConverter.ToString(premasterSecret, 0, premasterSecret.Length));

        }
    }
}
