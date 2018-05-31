using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using NetMQ.Security;
using NetMQ.Security.Extensions;
using NetMQ.Security.V0_1;
using NetMQ.Sockets;
using NUnit.Framework;

namespace NetMQ.Security.Tests
{
    [TestFixture]
    public class V3_3SecureChannelTests
    {
        private SecureChannel m_clientSecureChannel;
        private SecureChannel m_serverSecureChannel;
        [SetUp]
        public void Setup()
        {
            Configuration configuration = new Configuration(){ VerifyCertificate = false, StandardTLSFormat = true };
            X509Certificate2 certificate = new X509Certificate2(NUnit.Framework.TestContext.CurrentContext.TestDirectory + "\\server.pfx", "1234");

            m_serverSecureChannel = new SecureChannel(ConnectionEnd.Server, configuration) { Certificate = certificate };

            m_clientSecureChannel = new SecureChannel(ConnectionEnd.Client, configuration);

            IList<NetMQMessage> clientOutgoingMessages = new List<NetMQMessage>();
            IList<NetMQMessage> serverOutgoingMessages = new List<NetMQMessage>();

            bool serverComplete = false;

            bool clientComplete = m_clientSecureChannel.ProcessMessage(null, clientOutgoingMessages);

            while (!serverComplete || !clientComplete)
            {
                if (!serverComplete)
                {
                    foreach (var message in clientOutgoingMessages)
                    {
                        serverComplete = m_serverSecureChannel.ProcessMessage(message, serverOutgoingMessages);

                        if (serverComplete)
                        {
                            break;
                        }
                    }

                    clientOutgoingMessages.Clear();
                }

                if (!clientComplete)
                {
                    foreach (var message in serverOutgoingMessages)
                    {
                        clientComplete = m_clientSecureChannel.ProcessMessage(message, clientOutgoingMessages);

                        if (clientComplete)
                        {
                            break;
                        }
                    }

                    serverOutgoingMessages.Clear();
                }
            }
        }

        [TearDown]
        public void Teardown()
        {
            m_clientSecureChannel.Dispose();
            m_serverSecureChannel.Dispose();
        }

        [Test]
        public void Handshake()
        {
            Assert.IsTrue(m_clientSecureChannel.SecureChannelReady);
            Assert.IsTrue(m_serverSecureChannel.SecureChannelReady);
        }

        [Test]
        public void ClientToServerMessage()
        {
            NetMQMessage plainMessage = new NetMQMessage();
            plainMessage.Append("Hello");

            NetMQMessage cipherMessage = m_clientSecureChannel.EncryptApplicationMessage(plainMessage);

            NetMQMessage decryptedMessage = m_serverSecureChannel.DecryptApplicationMessage(cipherMessage);

            Assert.AreEqual(decryptedMessage[0].ConvertToString(), plainMessage[0].ConvertToString());
            Assert.AreEqual(decryptedMessage[0].ConvertToString(), "Hello");
        }

        [Test]
        public void ServerToClient()
        {
            NetMQMessage plainMessage = new NetMQMessage();
            plainMessage.Append("Hello");

            NetMQMessage cipherMessage = m_serverSecureChannel.EncryptApplicationMessage(plainMessage);

            NetMQMessage decryptedMessage = m_clientSecureChannel.DecryptApplicationMessage(cipherMessage);

            Assert.AreEqual(decryptedMessage[0].ConvertToString(), plainMessage[0].ConvertToString());
            Assert.AreEqual(decryptedMessage[0].ConvertToString(), "Hello");
        }

        [Test]
        public void TwoWayMessaging()
        {
            // server to client
            NetMQMessage plainMessage = new NetMQMessage();
            plainMessage.Append("Hello");
            NetMQMessage cipherMessage = m_serverSecureChannel.EncryptApplicationMessage(plainMessage);
            NetMQMessage decryptedMessage = m_clientSecureChannel.DecryptApplicationMessage(cipherMessage);
            Assert.AreEqual(decryptedMessage[0].ConvertToString(), plainMessage[0].ConvertToString());

            // client to server
            plainMessage = new NetMQMessage();
            plainMessage.Append("Reply");
            cipherMessage = m_clientSecureChannel.EncryptApplicationMessage(plainMessage);
            decryptedMessage = m_serverSecureChannel.DecryptApplicationMessage(cipherMessage);
            Assert.AreEqual(decryptedMessage[0].ConvertToString(), plainMessage[0].ConvertToString());
        }

        [Test]
        public void MultipartMessage()
        {
            NetMQMessage plainMessage = new NetMQMessage();
            plainMessage.Append("Hello");
            plainMessage.Append("World");

            NetMQMessage cipherMessage = m_serverSecureChannel.EncryptApplicationMessage(plainMessage);
            NetMQMessage decryptedMessage = m_clientSecureChannel.DecryptApplicationMessage(cipherMessage);
            Assert.AreEqual(decryptedMessage[0].ConvertToString(), plainMessage[0].ConvertToString());
            Assert.AreEqual(decryptedMessage[1].ConvertToString(), plainMessage[1].ConvertToString());
            Assert.AreEqual(decryptedMessage[0].ConvertToString(), "Hello");
            Assert.AreEqual(decryptedMessage[1].ConvertToString(), "World");
        }

        [Test]
        public void EmptyMessge()
        {
            NetMQMessage plainMessage = new NetMQMessage();

            NetMQMessage cipherMessage = m_serverSecureChannel.EncryptApplicationMessage(plainMessage);
            NetMQMessage decryptedMessage = m_clientSecureChannel.DecryptApplicationMessage(cipherMessage);

            Assert.AreEqual(decryptedMessage.FrameCount, 0);
        }

        [Test]
        public void WrongProtocolVersion()
        {
            NetMQMessage plainMessage = new NetMQMessage();
            plainMessage.Append("Hello");

            NetMQMessage cipherMessage = m_serverSecureChannel.EncryptApplicationMessage(plainMessage);

            // changing the protocol version
            cipherMessage[1].Buffer[0] = 99;

            NetMQSecurityException exception = Assert.Throws<NetMQSecurityException>(() => m_clientSecureChannel.DecryptApplicationMessage(cipherMessage));

            Assert.AreEqual(exception.ErrorCode, NetMQSecurityErrorCode.InvalidProtocolVersion);
        }

        [Test]
        public void WrongFramesCount()
        {
            NetMQMessage plainMessage = new NetMQMessage();
            plainMessage.Append("Hello");

            NetMQMessage cipherMessage = m_serverSecureChannel.EncryptApplicationMessage(plainMessage);

            // remove the first frame
            cipherMessage.RemoveFrame(cipherMessage.Last);

            NetMQSecurityException exception = Assert.Throws<NetMQSecurityException>(() => m_clientSecureChannel.DecryptApplicationMessage(cipherMessage));

            Assert.AreEqual(NetMQSecurityErrorCode.EncryptedFramesMissing, exception.ErrorCode);
        }

        [Test]
        public void ReorderFrames()
        {
            NetMQMessage plainMessage = new NetMQMessage();
            plainMessage.Append("Hello");
            plainMessage.Append("World");

            NetMQMessage cipherMessage = m_serverSecureChannel.EncryptApplicationMessage(plainMessage);

            NetMQMessage temp = new NetMQMessage(cipherMessage.FrameCount);
            while(cipherMessage.FrameCount > 4)
            {
                temp.Append(cipherMessage.Pop());
            }
            NetMQFrame oneBeforeLastLengthFrame = cipherMessage.Pop();
            NetMQFrame oneBeforeLastFrame = cipherMessage.Pop();

            NetMQFrame lastLengthFrame = cipherMessage.Pop();
            NetMQFrame lastFrame = cipherMessage.Pop();

            temp.Append(lastLengthFrame);
            temp.Append(lastFrame);
            temp.Append(oneBeforeLastLengthFrame);
            temp.Append(oneBeforeLastFrame);
            cipherMessage = temp;
            NetMQSecurityException exception = Assert.Throws<NetMQSecurityException>(() => m_clientSecureChannel.DecryptApplicationMessage(cipherMessage));

            Assert.AreEqual(NetMQSecurityErrorCode.MACNotMatched, exception.ErrorCode);
        }

        [Test]
        public void ChangeEncryptedBytesData()
        {
            NetMQMessage plainMessage = new NetMQMessage();
            plainMessage.Append("Hello");

            NetMQMessage cipherMessage = m_serverSecureChannel.EncryptApplicationMessage(plainMessage);

            cipherMessage.Last.Buffer[0]++;

            NetMQSecurityException exception = Assert.Throws<NetMQSecurityException>(() => m_clientSecureChannel.DecryptApplicationMessage(cipherMessage));

            Assert.AreEqual(NetMQSecurityErrorCode.MACNotMatched, exception.ErrorCode);
        }


        [Test]
        public void BigBytesData()
        {
            NetMQMessage plainMessage = new NetMQMessage();
            plainMessage.Append(new byte[1024*1024]);

            NetMQMessage cipherMessage = m_serverSecureChannel.EncryptApplicationMessage(plainMessage);

           var plainMessage1 = m_clientSecureChannel.DecryptApplicationMessage(cipherMessage);
            Assert.AreEqual(plainMessage.FrameCount, plainMessage1.FrameCount);
            Assert.AreEqual(plainMessage.Last.Buffer, plainMessage1.Last.Buffer);
        }
        [Test]
        public void MutiThreadEncryptDecrypt()
        {
            AutoResetEvent autoResetEvent = new AutoResetEvent(false);
            int count = 0;
            for (int i = 0; i < 4; i++)
            {
                Thread  thread = new Thread(()=>
                {
                    try
                    {
                        for(int j = 0; j <500; j ++)
                        {
                            NetMQMessage plainMessage1 = new NetMQMessage();
                            plainMessage1.Append("Hello");
                            NetMQMessage cipherMessage1 = m_serverSecureChannel.EncryptApplicationMessage(plainMessage1);
                            byte [] combineBytes = new byte[0];
                            foreach (var frame in cipherMessage1)
                            {
                                combineBytes = combineBytes.Combine(frame.Buffer);
                            }
                            bool change= true;
                            int offet = 0;
                            combineBytes.GetV0_2RecordLayerNetMQMessage(ref change,ref offet,out cipherMessage1);
                            NetMQMessage decryptedMessage1 = m_clientSecureChannel.DecryptApplicationMessage(cipherMessage1);

                            Assert.AreEqual(decryptedMessage1[0].ConvertToString(), plainMessage1[0].ConvertToString());
                            Assert.AreEqual(decryptedMessage1[0].ConvertToString(), "Hello");
                        }
                        Interlocked.Increment(ref count);
                        if(count == 4)
                        {
                            autoResetEvent.Set();
                        }
                    }
                    catch(Exception exception)
                    {
                        Console.WriteLine(exception);
                        autoResetEvent.Set();
                        Assert.IsTrue(false);
                    }
                });
                thread.IsBackground = true;
                thread.Start();
            }
            autoResetEvent.WaitOne();
        }



        [Test]
        public void SendReceiveMutiThreadEncryptDecrypt()
        {
            StreamSocket server = new StreamSocket();
            server.Bind("tcp://*:12345");
            StreamSocket client = new StreamSocket();
            client.Connect("tcp://*:12345");

            int count = 0;
            try
            {
                for (int j = 0; j < 500; j++)
                {
                    NetMQMessage plainMessage1 = new NetMQMessage();
                    plainMessage1.Append("Hello");
                    NetMQMessage cipherMessage1 = m_clientSecureChannel.EncryptApplicationMessage(plainMessage1);
                    byte [] combineBytes = new byte[0];
                    foreach (var frame in cipherMessage1)
                    {
                        combineBytes = combineBytes.Combine(frame.Buffer);
                    }
                    for (int i = 0; i < 500; i++)
                    {
                        client.SendMoreFrame(client.Options.Identity);
                        client.SendMoreFrame(BitConverter.GetBytes(combineBytes.Length).Combine(combineBytes));
                    }
                    NetMQMessage message = null;
                    byte[] buffer = new byte[0];
                    while (server.TryReceiveMultipartMessage(ref message))
                    {
                        buffer.Combine(message.Last.Buffer);
                        while (buffer.Length > 4)
                        {
                            Byte[] lengthBytes = new byte[4];
                            int length = BitConverter.ToInt32(lengthBytes, 0);
                            if(buffer.Length - 4 > length)
                            {
                                byte[]databytes = new byte[length];
                                Buffer.BlockCopy(buffer, 0, databytes, 0, length);
                                byte[] temp = new byte[buffer.Length - length];
                                Buffer.BlockCopy(buffer, length, temp, 0, buffer.Length - length);
                                buffer = temp;

                                
                                bool change= true;
                                int offet = 0;
                                databytes.GetV0_2RecordLayerNetMQMessage(ref change, ref offet, out cipherMessage1);
                                NetMQMessage decryptedMessage = m_serverSecureChannel.DecryptApplicationMessage(cipherMessage1);
                                Assert.AreEqual(decryptedMessage[0].ConvertToString(), plainMessage1[0].ConvertToString());
                                Assert.AreEqual(decryptedMessage[0].ConvertToString(), "Hello");
                                cipherMessage1 = m_serverSecureChannel.EncryptApplicationMessage(decryptedMessage);
                                cipherMessage1.GetLength(lengthBytes);
                                lengthBytes = lengthBytes.Combine(cipherMessage1.Last.Buffer);
                                decryptedMessage.RemoveFrame(decryptedMessage.Last);
                                decryptedMessage.Append(lengthBytes);
                            }
                        }
                        server.SendMultipartMessage(message);
                    }
                }
                Interlocked.Increment(ref count);
            }
            catch (Exception exception)
            {
                Console.WriteLine(exception);
                Assert.IsTrue(false);
            }
        }
        [Test]
        public void ChangeEncryptedFrameLength()
        {
            NetMQMessage plainMessage = new NetMQMessage();
            plainMessage.Append("Hello");

            NetMQMessage cipherMessage = m_serverSecureChannel.EncryptApplicationMessage(plainMessage);

            cipherMessage.RemoveFrame(cipherMessage.Last);

            // appending new frame with length different then block size
            cipherMessage.Append("Hello");

            NetMQSecurityException exception = Assert.Throws<NetMQSecurityException>(() => m_clientSecureChannel.DecryptApplicationMessage(cipherMessage));

            Assert.AreEqual(NetMQSecurityErrorCode.EncryptedFrameInvalidLength, exception.ErrorCode);
        }

        [Test]
        public void ChangeThePadding()
        {
            NetMQMessage plainMessage = new NetMQMessage();
            plainMessage.Append("Hello");

            NetMQMessage cipherMessage = m_serverSecureChannel.EncryptApplicationMessage(plainMessage);

            cipherMessage.Last.Buffer[15]++;

            NetMQSecurityException exception = Assert.Throws<NetMQSecurityException>(() => m_clientSecureChannel.DecryptApplicationMessage(cipherMessage));

            Assert.AreEqual(NetMQSecurityErrorCode.MACNotMatched, exception.ErrorCode);
        }

        [Test]
        public void ReplayAttach()
        {
            NetMQMessage plainMessage = new NetMQMessage();

            NetMQMessage cipherMessage = m_serverSecureChannel.EncryptApplicationMessage(plainMessage);

            // make a copy of the message because the method alter the current message
            NetMQMessage cipherMessageCopy = new NetMQMessage(cipherMessage);

            m_clientSecureChannel.DecryptApplicationMessage(cipherMessage);

            NetMQSecurityException exception = Assert.Throws<NetMQSecurityException>(() => m_clientSecureChannel.DecryptApplicationMessage(cipherMessageCopy));

            Assert.AreEqual(NetMQSecurityErrorCode.ReplayAttack, exception.ErrorCode);
        }

        [Test]
        public void DecryptingOldMessage()
        {
            NetMQMessage plainMessage = new NetMQMessage();

            NetMQMessage cipherMessage = m_serverSecureChannel.EncryptApplicationMessage(plainMessage);

            // copy of the first message, we are actually never try to decrypt the first message 
            // (to make sure the exception is because of the old message and not because the message was decrypted twice).
            NetMQMessage cipherMessageCopy = new NetMQMessage(cipherMessage);

            // the window size is 1024, we to decrypt 1024 messages before trying to decrypt the old message
            for (int i = 0; i < 1025; i++)
            {
                plainMessage = new NetMQMessage();

                cipherMessage = m_serverSecureChannel.EncryptApplicationMessage(plainMessage);
                m_clientSecureChannel.DecryptApplicationMessage(cipherMessage);
            }

            NetMQSecurityException exception = Assert.Throws<NetMQSecurityException>(() => m_clientSecureChannel.DecryptApplicationMessage(cipherMessageCopy));

            Assert.AreEqual(NetMQSecurityErrorCode.ReplayAttack, exception.ErrorCode);
        }

        [Test]
        public void DecryptOutOfOrder()
        {
            NetMQMessage plain1 = new NetMQMessage();
            plain1.Append("1");

            NetMQMessage plain2 = new NetMQMessage();
            plain2.Append("2");

            NetMQMessage cipher1 = m_clientSecureChannel.EncryptApplicationMessage(plain1);
            NetMQMessage cipher2 = m_clientSecureChannel.EncryptApplicationMessage(plain2);

            NetMQMessage decrypted2 = m_serverSecureChannel.DecryptApplicationMessage(cipher2);
            NetMQMessage decrypted1 = m_serverSecureChannel.DecryptApplicationMessage(cipher1);

            Assert.AreEqual(decrypted1[0].ConvertToString(), "1");
            Assert.AreEqual(decrypted2[0].ConvertToString(), "2");
        }
    }
}
