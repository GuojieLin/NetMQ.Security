using NetMQ.Security.V0_1;
using NetMQ.Sockets;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace NetMQ.Console
{
    class Client
    {
        public void Do()
        {

            using (var socket = new DealerSocket())
            {
                socket.Connect("tcp://127.0.0.1:5556");

                SecureChannel secureChannel = new SecureChannel(ConnectionEnd.Client);

                // we are not using signed certificate so we need to validate 
                // the certificate of the server, by default the secure channel 
                // is checking that the source of the 
                // certitiface is a root certificate authority
                //secureChannel.SetVerifyCertificate(c => true);

                // we need to set X509Certificate with a private key for the server
                X509Certificate2 certificate = new X509Certificate2(
                    System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"client.pfx"),"1234");
                secureChannel.Certificate = certificate;

                List<NetMQMessage> outgoingMessages = new List<NetMQMessage>();

                // call the process message with null as the incoming message 
                // because the client is initiating the connection
                secureChannel.ProcessMessage(null, outgoingMessages);
                //Server.SendMessages(socket, outgoingMessages);

                foreach (NetMQMessage message in outgoingMessages)
                {
                    socket.SendMultipartMessage(message);
                }
                outgoingMessages.Clear();
                // waiting for a message from the server
                NetMQMessage incomingMessage= socket.ReceiveMultipartMessage();

                // calling ProcessMessage until ProcessMessage return true 
                // and the SecureChannel is ready to encrypt and decrypt messages
                while (!secureChannel.ProcessMessage(incomingMessage, outgoingMessages))
                {

                    foreach (NetMQMessage message in outgoingMessages)
                    {
                        socket.SendMultipartMessage(message);
                    }
                    outgoingMessages.Clear();
                    //Server.SendMessages(socket, outgoingMessages);
                    incomingMessage = socket.ReceiveMultipartMessage();
                }

                foreach (NetMQMessage message in outgoingMessages)
                {
                    socket.SendMultipartMessage(message);
                }
                outgoingMessages.Clear();
                //Server.SendMessages(socket, outgoingMessages);
                // you can now use the secure channel to encrypt messages
                NetMQMessage plainMessage = new NetMQMessage();
                plainMessage.Append("Hello");

                // encrypting the message and sending it over the socket
                socket.SendMultipartMessage(secureChannel.EncryptApplicationMessage(plainMessage));
            }

        }
    }
}
