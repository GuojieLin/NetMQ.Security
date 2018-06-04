using NetMQ.Security;
using NetMQ.Security.V0_1;
using NetMQ.Sockets;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace NetMQ.Console
{
    class Server
    {
        Configuration m_configuration;
        public Server(Configuration configuration)
        {
            m_configuration = configuration;
        }
        public void Do()
        {
            // we are using dealer here, but we can use router as well, we just have to manager
            // SecureChannel for each identity
            using (var socket = new DealerSocket())
            {
                socket.Bind("tcp://*:5556");

                using (SecureChannel secureChannel = SecureChannel.CreateServerSecureChannel(m_configuration))
                {

                    // we need to set X509Certificate with a private key for the server
                    X509Certificate2 certificate = new X509Certificate2(
                    System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"server.pfx"),"1234");
                    secureChannel.Certificate = certificate;

                    List<NetMQMessage> outgoingMessages = new List<NetMQMessage>();

                    // waiting for message from client
                    NetMQMessage incomingMessage = socket.ReceiveMultipartMessage();
                    //SplitInMessage

                    // calling ProcessMessage until ProcessMessage return true 
                    // and the SecureChannel is ready to encrypt and decrypt messages
                    while (!secureChannel.ProcessMessage(incomingMessage, outgoingMessages))
                    {
                        //SendMessages(socket,outgoingMessages);
                        foreach (NetMQMessage message in outgoingMessages)
                        {
                            socket.SendMultipartMessage(message);
                        }
                        outgoingMessages.Clear();
                        incomingMessage = socket.ReceiveMultipartMessage();
                    }
                    //SendMessages(socket, outgoingMessages);
                    foreach (NetMQMessage message in outgoingMessages)
                    {
                        socket.SendMultipartMessage(message);
                    }
                    outgoingMessages.Clear();

                    // this message is now encrypted
                    NetMQMessage cipherMessage = socket.ReceiveMultipartMessage();

                    // decrypting the message
                    NetMQMessage plainMessage = secureChannel.DecryptApplicationMessage(cipherMessage);
                    System.Console.WriteLine(plainMessage.First.ConvertToString());
                    plainMessage = new NetMQMessage();
                    plainMessage.Append("Worldddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");

                    // encrypting the message and sending it over the socket
                    socket.SendMultipartMessage(secureChannel.EncryptApplicationMessage(plainMessage));
                }
            }

        }

        public static void SendMessages(StreamSocket socket, List<NetMQMessage> outgoingMessages)
        {
            NetMQMessage message = new NetMQMessage();
            message.Append(socket.Options.Identity);
            byte[] handsharkbytes = null;
            //需要将消息合并一次性发出
            // the process message method fill the outgoing messages list with 
            // messages to send over the socket
            foreach (NetMQMessage outgoingMessage in outgoingMessages)
            {
                foreach (NetMQFrame frame in outgoingMessage)
                {
                    if (handsharkbytes == null)
                    {
                        handsharkbytes = frame.Buffer;
                        continue;
                    }
                    handsharkbytes = Server.CombineV2(handsharkbytes, frame.Buffer);
                }
            }
            outgoingMessages.Clear();
            message.Append(handsharkbytes);
            socket.SendMultipartMessage(message);
        }
        public static byte[] CombineV2(byte[] bytes1, byte[] bytes2)
        {
            byte[] c = new byte[bytes1.Length + bytes2.Length];

            Buffer.BlockCopy(bytes1, 0, c, 0, bytes1.Length);
            Buffer.BlockCopy(bytes2, 0, c, bytes1.Length, bytes2.Length);
            return c;
        }
    }
}
