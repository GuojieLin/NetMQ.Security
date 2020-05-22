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

            Configuration configuration = new Configuration(){ VerifyCertificate = false};
            //Server server = new Server(configuration);
            //Action action1 = server.Do;
            //action1.BeginInvoke(ac => { action1.EndInvoke(ac); }, null);
            //Client client = new Client(configuration);
            //Action action2 = client.Do;
            //action2.BeginInvoke(ac => { action2.EndInvoke(ac); }, null);
            StreamServer server = new StreamServer(configuration);
            //SSLClient server = new SSLClient(configuration);
            Action action1 = server.Do;
            action1.BeginInvoke(ac => { action1.EndInvoke(ac); }, null);
            System.Console.ReadKey();
            RSADe.Do2("a8804a95f3bb38e864265e1f1eff7d434fb4197e78bc175f7fdb29e4b68d9b62d7207b87837b40932c26d3cfb299ef68c337012c09acc34d568bce03a0ef1f9be5c8ab492cf86d9d7c8be1868edde1a657bf5bfb088cd55535cc22c05ab34a61857f2c4e513f3629fb4848f627e295a81012fc25b5a6d98fe8457909413def71");
        }
    }
}