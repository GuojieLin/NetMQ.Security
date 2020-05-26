using NetMQ.Security;
using NetMQ.Security.Extensions;
using NetMQ.Security.TLS12;
using NetMQ.Sockets;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace NetMQ.Console
{
    class SSLClient
    {
        Configuration m_configuration;
        public SSLClient(Configuration configuration)
        {
            m_configuration = configuration;
        }
        public void Do()
        {
            // we are using dealer here, but we can use router as well, we just have to manager
            // SecureChannel for each identity
            using (var socket = new StreamSocket())
            {
                socket.Connect("tcp://127.0.0.1:9696");

                using (SecureChannel secureChannel = SecureChannel.CreateClientSecureChannel(null,m_configuration))
                {
                    secureChannel.AllowedCipherSuites = new []{ CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA };
                    // we need to set X509Certificate with a private key for the server
                    X509Certificate2 certificate = new X509Certificate2(
                    System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"server.pfx"),"1234");
                    secureChannel.Certificate = certificate;
                    List<NetMQMessage> outgoingMessages = new List<NetMQMessage>();
                    bool clientComplete = secureChannel.ProcessMessage(null, outgoingMessages);

                    SendMessages(socket, outgoingMessages);
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
                    for (int i = 0; i < 10; i++)
                    {
                        outgoingMessages.Clear();

                        NetMQMessage plainMessage = new NetMQMessage();
                        byte[] data = Encoding.GetEncoding("GBK").GetBytes("10009<Root><Head><CommandCode>10009</CommandCode><TransSeqID>2020051514384165</TransSeqID><VerifyCode>MbzZvbTp9Cnw9iqvRjJ3in6wNry59ZB1ubSCpWxeRiov9eU0c8MCGTE+u+7ED7NlU4EA8mf+OATBvS6OlgYzggKmsEt6CoPhQB3V/xzMZzlLGwym7r1arrNYIUjW6oJKXWNe84SYTe8Mqfw1+gmzEcj72QpadujHdDTJ9WNEsmg=</VerifyCode><ZipType></ZipType><CorpBankCode>103</CorpBankCode><FGCommandCode>11111</FGCommandCode><EnterpriseNum>AS330106</EnterpriseNum><TransKeyEncryptFlag>0</TransKeyEncryptFlag><FGVerifyCode>nQuCJ41Gp1wuankSkCvscwFVISkdI0XoGUJwKTB9IS7dbg+OgxpHe/zdSQkIZQjZbS5rzkFlmx31mrR8cmZa/jXJ+r4xeBfncS6qKJdYEH4jJra4/JyFkcb2mE8yolxN3v1C/M/Kq2+d532oXuQfiBqkEAv3gSb30zjurtVs3+I=</FGVerifyCode></Head><RealTimeSingleTransReq><MoneyWay>2</MoneyWay><TransDate>20200515</TransDate><Trans><TransNo>testClwTLS20200515003</TransNo><ProtocolCode></ProtocolCode><EnterpriseAccNum>19030101040014391</EnterpriseAccNum><CustBankCode>103</CustBankCode><CustAccNum>12312312</CustAccNum><CustAccName>陈大帅逼</CustAccName><AreaCode></AreaCode><BankLocationCode></BankLocationCode><BankLocationName></BankLocationName><CardType></CardType><IsPrivate>0</IsPrivate><IsUrgent></IsUrgent><Amount>232.00</Amount><Currency>CNY</Currency><CertType>0</CertType><CertNum></CertNum><Mobile></Mobile><Purpose></Purpose><Memo></Memo><PolicyNumber></PolicyNumber><Extent1></Extent1><Extent2></Extent2><SourceTransNo>testClwTLS20200515003</SourceTransNo></Trans></RealTimeSingleTransReq></Root>");
                        string length = data.Length.ToString().PadLeft(8, ' ');
                        plainMessage.Append(length);
                        plainMessage.Append(data);

                        socket.SendMoreFrame(socket.Options.Identity);
                        socket.SendFrame(secureChannel.EncryptApplicationMessage(plainMessage)[0].Buffer);

                        // this message is now encrypted
                        NetMQMessage cipherMessage = socket.ReceiveMultipartMessage();
                        int offset2;
                        List<NetMQMessage> sslMessages2;
                        secureChannel.ResolveRecordLayer(cipherMessage.Last.Buffer, out offset2, out sslMessages2);
                        // decrypting the message
                        plainMessage = secureChannel.DecryptApplicationMessage(sslMessages2[0]);
                        System.Console.WriteLine(plainMessage.First.ConvertToString());
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
