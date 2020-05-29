using NetMQ.Security;
using NetMQ.Security.Extensions;
using NetMQ.Security.Layer;
using NetMQ.Security.TLS12;
using NetMQ.Sockets;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace NetMQ.Console
{
    class StreamServer
    {
        Configuration m_configuration;
        public StreamServer(Configuration configuration)
        {
            m_configuration = configuration;
        }
        public static void SendMessages(StreamSocket socket, List<RecordLayer> outgoingMessages)
        {
            if (!outgoingMessages.Any()) return;
            //需要将消息合并一次性发出
            // the process message method fill the outgoing messages list with 
            // messages to send over the socket
            foreach (RecordLayer outgoingMessage in outgoingMessages)
            {
                NetMQMessage message = new NetMQMessage();
                message.Append(socket.Options.Identity);
                message.Append(outgoingMessage);
                socket.SendMultipartMessage(message);
            }
            outgoingMessages.Clear();
        }
        public void Do2()
        {
            // we are using dealer here, but we can use router as well, we just have to manager
            // SecureChannel for each identity
            using (var socket = new StreamSocket())
            {
                socket.Bind("tcp://*:9696");

                using (SecureChannel secureChannel = SecureChannel.CreateServerSecureChannel(m_configuration))
                {

                    // we need to set X509Certificate with a private key for the server
                    X509Certificate2 certificate = new X509Certificate2(
                    System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "server.pfx"), "1234");
                    secureChannel.Certificate = certificate;

                    List<RecordLayer> outgoingMessages = new List<RecordLayer>();
                    bool done = false;
                    // waiting for message from client
                    byte[] cache = null;
                    do
                    {
                        outgoingMessages.Clear();
                        NetMQMessage incomingMessage = socket.ReceiveMultipartMessage();
                        if (cache == null || cache.Length <= 0)
                        {
                            cache = incomingMessage.Last.Buffer;
                        }
                        else
                        {
                            cache = CombineV2(cache, incomingMessage.Last.Buffer);
                        }
                        ReadonlyBuffer<byte> buffer = new ReadonlyBuffer<byte>(cache);
                        //SplitInMessage
                        done = secureChannel.ResolveRecordLayer(buffer, outgoingMessages);
                        SendMessages(socket, outgoingMessages);
                        if (buffer.Length == 0)
                        {
                            cache = null;
                        }
                        else
                        {
                            cache = buffer;
                        }
                    } while (!done);
                    SendMessages(socket, outgoingMessages);
                    outgoingMessages.Clear();
                    cache = null;
                    while (true)
                    {
                        // this message is now encrypted
                        NetMQMessage cipherMessage = socket.ReceiveMultipartMessage();
                        if (cache == null || cache.Length <= 0)
                        {
                            cache = cipherMessage.Last.Buffer;
                        }
                        else
                        {
                            cache = CombineV2(cache, cipherMessage.Last.Buffer);
                        }
                        ReadonlyBuffer<byte> buffer = new ReadonlyBuffer<byte>(cache);
                        List<RecordLayer> sslMessages2 = new List<RecordLayer>();
                        if (secureChannel.ResolveRecordLayer(buffer, sslMessages2))
                        {
                            foreach (var message in sslMessages2)
                            {
                                // decrypting the message
                                byte[] plainMessage = secureChannel.DecryptApplicationData(message.RecordProtocols[0].HandShakeData);
                                System.Console.WriteLine(Encoding.GetEncoding("GBK").GetString(plainMessage));
                                ReadonlyBuffer<byte> sendBuffer = new ReadonlyBuffer<byte>(Encoding.GetEncoding("GBK").GetBytes("00000021<Root>TestResp</Root>"));
                                var recordLayer = secureChannel.EncryptApplicationData(sendBuffer);

                                socket.SendMoreFrame(socket.Options.Identity);
                                socket.SendFrame(recordLayer);
                            }
                        }
                        if (buffer.Length == 0)
                        {
                            cache = null;
                        }
                        else
                        {
                            cache = buffer;
                        }
                    }
                    // encrypting the message and sending it over the socket
                }
            }

        }
        public void Do()
        {
            // we are using dealer here, but we can use router as well, we just have to manager
            // SecureChannel for each identity
            using (var socket = new StreamSocket())
            {
                socket.Bind("tcp://*:9696");

                using (SecureChannel secureChannel = SecureChannel.CreateServerSecureChannel(m_configuration))
                {

                    // we need to set X509Certificate with a private key for the server
                    X509Certificate2 certificate = new X509Certificate2(
                    System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"server.pfx"),"1234");
                    secureChannel.Certificate = certificate;

                    List<NetMQMessage> outgoingMessages = new List<NetMQMessage>();
                    bool done = false;
                    // waiting for message from client
                    byte[] cache = null;
                    do
                    {
                        outgoingMessages.Clear();
                        NetMQMessage incomingMessage = socket.ReceiveMultipartMessage();
                        if (cache == null || cache.Length <= 0)
                        {
                            cache = incomingMessage.Last.Buffer;
                        }
                        else
                        {
                            cache = CombineV2(cache, incomingMessage.Last.Buffer);
                        }
                        //SplitInMessage
                        int offset;
                        List<NetMQMessage> sslMessages;
                        secureChannel.ResolveRecordLayer(cache, out offset, out sslMessages);
                        if(cache.Length == offset)
                        {
                            cache = null;
                        }
                        else if (cache.Length > offset)
                        {
                            byte[] temp = new byte[cache.Length - offset];
                            Buffer.BlockCopy(cache, offset, temp, 0, temp.Length);
                            cache = temp;
                        }
                        foreach (var sslMessage in sslMessages)
                        {
                            // calling ProcessMessage until ProcessMessage return true 
                            // and the SecureChannel is ready to encrypt and decrypt messages
                            done = secureChannel.ProcessMessage(sslMessage, outgoingMessages);
                            SendMessages(socket,outgoingMessages);
                        }
                    } while (!done);
                    SendMessages(socket, outgoingMessages);
                    outgoingMessages.Clear();
                    cache = null;
                    while (true)
                    {
                        // this message is now encrypted
                        NetMQMessage cipherMessage = socket.ReceiveMultipartMessage();
                        if (cache == null || cache.Length <= 0)
                        {
                            cache = cipherMessage.Last.Buffer;
                        }
                        else
                        {
                            cache = CombineV2(cache, cipherMessage.Last.Buffer);
                        }
                        int offset2;
                        List<NetMQMessage> sslMessages2;
                        secureChannel.ResolveRecordLayer(cache, out offset2, out sslMessages2);
                        if (cache.Length == offset2)
                        {
                            cache = null;
                        }
                        else if(offset2 == 0)
                        {
                            //长度不够，等下一次读取在解析
                            continue;
                        }
                        else if (cache.Length > offset2)
                        {
                            byte[] temp = new byte[cache.Length - offset2];
                            Buffer.BlockCopy(cache, offset2, temp, 0, temp.Length);
                            cache = temp;
                        }
                        if (sslMessages2.Count <= 0) continue;
                        // decrypting the message
                        NetMQMessage plainMessage = secureChannel.DecryptApplicationMessage(sslMessages2[0]);
                        System.Console.WriteLine(plainMessage.First.ConvertToString());
                        plainMessage = new NetMQMessage();
                        plainMessage.Append("00000021<Root>TestResp</Root>");

                        socket.SendMoreFrame(socket.Options.Identity);
                        socket.SendFrame(secureChannel.EncryptApplicationMessage(plainMessage)[0].Buffer);
                    }
                    // encrypting the message and sending it over the socket
                }
            }

        }

        public static void SendMessages(StreamSocket socket, List<NetMQMessage> outgoingMessages)
        {
            if (!outgoingMessages.Any()) return;
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

        internal static byte[] GetBytes(IList<NetMQMessage> respMessages)
        {
            byte[] data = new byte[0];

            //响应ssl握手包
            foreach (var resp in respMessages)
            {
                foreach (NetMQFrame frame in resp)
                {
                    data = data.Combine(frame.Buffer);
                }
            }
            return data;
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
