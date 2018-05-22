using NetMQ.Security;
using NetMQ.Security.V0_1;
using NetMQ.Sockets;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;

namespace NetMQ.Console
{
    class Program
    {
        public static void CreateX509()
        {

        }
        static void Main(string[] args)
        {
            //    System.Console.WriteLine("sha256:" + BitConverter.ToString(bytes) + ",r = "+r);
            //X509Certificate2 x509Root = new X509Certificate2(@"F:\Study\ubuntu\openssl\ca.crt");
            //System.Console.WriteLine("Root Certificate Verified?: {0}{1}", x509Root.Verify(), Environment.NewLine);
            // x509Root = new X509Certificate2(@"F:\Study\ubuntu\openssl\client.crt");
            //System.Console.WriteLine("Client Certificate Verified?: {0}{1}", x509Root.Verify(), Environment.NewLine);
            // x509Root = new X509Certificate2(@"F:\Study\ubuntu\openssl\server.crt");
            //System.Console.WriteLine("Server Certificate Verified?: {0}{1}", x509Root.Verify(), Environment.NewLine);
            //System.Console.ReadKey();
            //System.Console.WriteLine(Convert.ToBase64String(Encoding.Default.GetBytes("65537")));
            //X509Certificate2 myX509Certificate1 = new X509Certificate2(@"E:\Dm_ca\Documents\WeChat Files\WeChat Files\wxid_23befs6o3e9h22\Files\RMBP.cer");
            //byte[] bytes1 = myX509Certificate1.GetPublicKey();
            //RSACryptoServiceProvider myRSACryptoServiceProvider1 = (RSACryptoServiceProvider)myX509Certificate1.PublicKey.Key;
            //string xml1 =  myRSACryptoServiceProvider1.ToXmlString(false);
            //X509Certificate2 myX509Certificate2 = new X509Certificate2(@"F:\Study\ubuntu\openssl\client.crt");
            //byte[] bytes2 = myX509Certificate2.GetPublicKey();
            //var myRSACryptoServiceProvider2 = (RSACryptoServiceProvider)myX509Certificate2.PublicKey.Key;
            //var xml2 =  myRSACryptoServiceProvider2.ToXmlString(false);
            //RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();

            Configuration configuration = new Configuration(){ VerifyCertificate = false, StandardTLSFormat = false };
            Server server = new Server(configuration);
            Action action1 = server.Do;
            action1.BeginInvoke(ac => { action1.EndInvoke(ac); }, null);
            Client client = new Client(configuration);
            Action action2 = client.Do;
            action2.BeginInvoke(ac => { action2.EndInvoke(ac); }, null);
            System.Console.ReadKey();
        }
    }
}