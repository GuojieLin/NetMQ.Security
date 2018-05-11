using NetMQ.Security;
using NetMQ.Security.V0_1;
using NetMQ.Sockets;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

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
            Configuration configuration = new Configuration(){ VerifyCertificate = false, StandardTLSFormat = true };
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