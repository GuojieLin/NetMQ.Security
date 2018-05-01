using NetMQ.Security.V0_1;
using NetMQ.Sockets;
using System;
using System.Collections;
using System.Collections.Generic;

namespace NetMQ.Console
{
    class Program
    {
        public static void CreateX509()
        {

        }
        static void Main(string[] args)
        {
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
