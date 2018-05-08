using NetMQ.Security.V0_1;
using NetMQ.Sockets;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace NetMQ.Console
{
    class Program
    {
        public static void CreateX509()
        {

        }
        static void Main(string[] args)
        {
            X509Certificate2 x509Root = new X509Certificate2(@"F:\Study\ubuntu\openssl\ca.crt");
            System.Console.WriteLine("Root Certificate Verified?: {0}{1}", x509Root.Verify(), Environment.NewLine);
             x509Root = new X509Certificate2(@"F:\Study\ubuntu\openssl\client.crt");
            System.Console.WriteLine("Client Certificate Verified?: {0}{1}", x509Root.Verify(), Environment.NewLine);
             x509Root = new X509Certificate2(@"F:\Study\ubuntu\openssl\server.crt");
            System.Console.WriteLine("Server Certificate Verified?: {0}{1}", x509Root.Verify(), Environment.NewLine);
            System.Console.ReadKey();
            Server server = new Server();
            Action action1 = server.Do;
            action1.BeginInvoke(ac => { action1.EndInvoke(ac); }, null);
            Client client = new Client();
            Action action2 = client.Do;
            action2.BeginInvoke(ac => { action2.EndInvoke(ac); }, null);
            System.Console.ReadKey();
        }

    }
}
