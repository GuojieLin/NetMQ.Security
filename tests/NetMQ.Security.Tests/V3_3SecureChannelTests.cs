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
            Configuration configuration = new Configuration() { VerifyCertificate = false, StandardTLSFormat = true };
            X509Certificate2 certificate = new X509Certificate2(NUnit.Framework.TestContext.CurrentContext.TestDirectory + "\\server.pfx", "1234");

            m_serverSecureChannel = SecureChannel.CreateServerSecureChannel(configuration);
            m_serverSecureChannel.Certificate = certificate;

            m_clientSecureChannel = SecureChannel.CreateClientSecureChannel(null, configuration);

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
                        int offset;
                        List<NetMQMessage> sslMessages;
                        bool result = m_serverSecureChannel.ResolveRecordLayer(message.Last.Buffer, out offset, out sslMessages);
                        foreach (var sslMessage in sslMessages)
                        {
                            serverComplete = m_serverSecureChannel.ProcessMessage(sslMessage, serverOutgoingMessages);

                            if (serverComplete)
                            {
                                break;
                            }
                        }
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
                        int offset;
                        List<NetMQMessage> sslMessages;

                        bool result = m_clientSecureChannel.ResolveRecordLayer(message.Last.Buffer, out offset, out sslMessages);
                        foreach (var sslMessage in sslMessages)
                        {
                            clientComplete = m_clientSecureChannel.ProcessMessage(sslMessage, clientOutgoingMessages);

                            if (clientComplete)
                            {
                                break;
                            }
                        }
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

            bool changeCipherSepc = false;
            int offset;
            List<NetMQMessage> sslMessages;

            bool result = m_serverSecureChannel.ResolveRecordLayer(cipherMessage.First.Buffer, out offset, out sslMessages);


            Assert.AreEqual(sslMessages.Count, 1);
            cipherMessage = sslMessages[0];

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

            bool changeCipherSepc = false;
            int offset;
            List<NetMQMessage> sslMessages;
            bool result = m_clientSecureChannel.ResolveRecordLayer(cipherMessage.First.Buffer, out offset, out sslMessages);

            Assert.AreEqual(sslMessages.Count, 1);
            cipherMessage = sslMessages[0];
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

            bool changeCipherSepc = false;
            int offset;
            List<NetMQMessage> sslMessages;

            bool result = m_clientSecureChannel.ResolveRecordLayer(cipherMessage.First.Buffer, out offset, out sslMessages);


            Assert.AreEqual(sslMessages.Count, 1);
            cipherMessage = sslMessages[0];

            NetMQMessage decryptedMessage = m_clientSecureChannel.DecryptApplicationMessage(cipherMessage);
            Assert.AreEqual(decryptedMessage[0].ConvertToString(), plainMessage[0].ConvertToString());

            // client to server
            plainMessage = new NetMQMessage();
            plainMessage.Append("Reply");
            cipherMessage = m_clientSecureChannel.EncryptApplicationMessage(plainMessage);

            result = m_serverSecureChannel.ResolveRecordLayer(cipherMessage.First.Buffer, out offset, out sslMessages);

            Assert.AreEqual(sslMessages.Count, 1);
            cipherMessage = sslMessages[0];

            decryptedMessage = m_serverSecureChannel.DecryptApplicationMessage(cipherMessage);
            Assert.AreEqual(decryptedMessage[0].ConvertToString(), plainMessage[0].ConvertToString());
        }

        [Test]
        [Ignore("暂时不支持多个包一同加密")]
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

            int offset;
            List<NetMQMessage> sslMessages;


            bool result = m_clientSecureChannel.ResolveRecordLayer(cipherMessage.First.Buffer, out offset, out sslMessages);

            Assert.AreEqual(sslMessages.Count, 1);
            cipherMessage = sslMessages[0];
            NetMQMessage decryptedMessage = m_clientSecureChannel.DecryptApplicationMessage(cipherMessage);

            Assert.AreEqual(decryptedMessage[0].BufferSize, 0);
        }

        [Test]
        public void WrongProtocolVersion()
        {
            NetMQMessage plainMessage = new NetMQMessage();
            plainMessage.Append("Hello");

            NetMQMessage cipherMessage = m_serverSecureChannel.EncryptApplicationMessage(plainMessage);
            
            int offset;
            List<NetMQMessage> sslMessages;

            bool result = m_clientSecureChannel.ResolveRecordLayer(cipherMessage.First.Buffer, out offset, out sslMessages);
            

            Assert.AreEqual(sslMessages.Count, 1);
            cipherMessage = sslMessages[0];
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

            int offset;
            List<NetMQMessage> sslMessages;

            bool result = m_clientSecureChannel.ResolveRecordLayer(cipherMessage.First.Buffer, out offset, out sslMessages);

            Assert.AreEqual(sslMessages.Count, 1);
            cipherMessage = sslMessages[0];
            // remove the first frame
            cipherMessage.RemoveFrame(cipherMessage.Last);
            cipherMessage.RemoveFrame(cipherMessage.Last);
            cipherMessage.RemoveFrame(cipherMessage.Last);

            NetMQSecurityException exception = Assert.Throws<NetMQSecurityException>(() => m_clientSecureChannel.DecryptApplicationMessage(cipherMessage));

            Assert.AreEqual(NetMQSecurityErrorCode.InvalidFramesCount, exception.ErrorCode);
        }

        [Test]
        [Ignore("不支持多个ApplicationData")]
        public void ReorderFrames()
        {
            NetMQMessage plainMessage = new NetMQMessage();
            plainMessage.Append("Hello");
            plainMessage.Append("World");

            NetMQMessage cipherMessage = m_serverSecureChannel.EncryptApplicationMessage(plainMessage);
            
            int offset;
            List<NetMQMessage> sslMessages;

            bool result = m_clientSecureChannel.ResolveRecordLayer(cipherMessage.First.Buffer, out offset, out sslMessages);


            Assert.AreEqual(sslMessages.Count, 1);
            cipherMessage = sslMessages[0];
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
            
            int offset;
            List<NetMQMessage> sslMessages;

            bool result = m_clientSecureChannel.ResolveRecordLayer(cipherMessage.First.Buffer, out offset, out sslMessages);


            Assert.AreEqual(sslMessages.Count, 1);
            cipherMessage = sslMessages[0];

            cipherMessage.Last.Buffer[0]++;


            NetMQSecurityException exception = Assert.Throws<NetMQSecurityException>(() => m_clientSecureChannel.DecryptApplicationMessage(cipherMessage));

            Assert.AreEqual(NetMQSecurityErrorCode.MACNotMatched, exception.ErrorCode);
        }


        [TestCase(1)]
        [TestCase(1024)]
        [TestCase(18432)]
        [TestCase(18433)]
        [TestCase(65535)]
        [TestCase(1048576)]
        public void BigBytesData(int length)
        {
            NetMQMessage plainMessage = new NetMQMessage();
            plainMessage.Append(new byte[length]);
            new Random().NextBytes(plainMessage[0].Buffer);
            byte[]data = m_serverSecureChannel.EncryptApplicationBytes(plainMessage[0].Buffer);
            List< NetMQMessage> sslMessages = new List<NetMQMessage>();


            int o = 0;

            bool result = m_clientSecureChannel.ResolveRecordLayer(data, out o, out sslMessages);

            List< NetMQMessage> plainMessages = new List<NetMQMessage>();
            foreach (var netmq in sslMessages)
            {
                //大包合并包
                plainMessages.Add(m_clientSecureChannel.DecryptApplicationMessage(netmq));
            }
            Assert.AreEqual(plainMessage.Sum(p => p.BufferSize), plainMessages.Sum(f => f.Sum(p => p.BufferSize)));
            byte[] encryptBytes = new byte[plainMessages.Sum(e=>e.Sum(f=>f.BufferSize))];
            int offset = 0;
            foreach (var p in plainMessages)
            {
                foreach (var frame in p)
                {
                    Buffer.BlockCopy(frame.Buffer, 0, encryptBytes, offset, frame.BufferSize);
                    offset += frame.BufferSize;
                }
            }
            Assert.AreEqual(plainMessage[0].Buffer, encryptBytes);
        }
        [Test]
        public void MutiThreadEncryptDecrypt()
        {
            AutoResetEvent autoResetEvent = new AutoResetEvent(false);
            int count = 0;
            object lockObject= new object();
            Queue<NetMQMessage> queue = new Queue<NetMQMessage>(2000);
            bool finish = false;
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
                            lock (queue)
                            {
                                NetMQMessage cipherMessage1 = m_serverSecureChannel.EncryptApplicationMessage(plainMessage1);
                                queue.Enqueue(cipherMessage1);
                            }
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

                thread = new Thread(() =>
                {
                    try
                    {
                        while(!finish)
                        {
                            NetMQMessage cipherMessage1;
                            lock (queue)
                            {
                                cipherMessage1 = queue.Dequeue();
                            }
                            int offet = 0;
                            List<NetMQMessage> sslMessages;
                            m_clientSecureChannel.ResolveRecordLayer(cipherMessage1[0].Buffer, out offet, out sslMessages);

                            NetMQMessage decryptedMessage1 = m_clientSecureChannel.DecryptApplicationMessage(sslMessages[0]);
                            Assert.AreEqual(decryptedMessage1[0].ConvertToString(), "Hello");
                        }
                        Interlocked.Increment(ref count);
                        if (count == 4)
                        {
                            autoResetEvent.Set();
                        }
                    }
                    catch (Exception exception)
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
            finish = true;
        }


        [Test]
        public void ChangeEncryptedFrameLength()
        {
            NetMQMessage plainMessage = new NetMQMessage();
            plainMessage.Append("Hello");

            NetMQMessage cipherMessage = m_serverSecureChannel.EncryptApplicationMessage(plainMessage);


            int offset;
            List<NetMQMessage> sslMessages;

            bool result = m_clientSecureChannel.ResolveRecordLayer(cipherMessage.First.Buffer, out offset, out sslMessages);


            Assert.AreEqual(sslMessages.Count, 1);
            cipherMessage = sslMessages[0];

            cipherMessage.RemoveFrame(cipherMessage.Last);

            // appending new frame with length different then block size
            cipherMessage.Append("ChangeEncryptedFrame");

            NetMQSecurityException exception = Assert.Throws<NetMQSecurityException>(() => m_clientSecureChannel.DecryptApplicationMessage(cipherMessage));

            Assert.AreEqual(NetMQSecurityErrorCode.EncryptedFrameInvalidLength, exception.ErrorCode);
        }

        [Test]
        public void ChangeThePadding()
        {
            NetMQMessage plainMessage = new NetMQMessage();
            plainMessage.Append("Hello");

            NetMQMessage cipherMessage = m_serverSecureChannel.EncryptApplicationMessage(plainMessage);
            
            int offset;
            List<NetMQMessage> sslMessages;

            bool result = m_clientSecureChannel.ResolveRecordLayer(cipherMessage.First.Buffer, out offset, out sslMessages);


            Assert.AreEqual(sslMessages.Count, 1);
            cipherMessage = sslMessages[0];

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
            
            int offset;
            List<NetMQMessage> sslMessages;

            bool result = m_clientSecureChannel.ResolveRecordLayer(cipherMessage.First.Buffer, out offset, out sslMessages);

            Assert.AreEqual(sslMessages.Count, 1);
            cipherMessage = sslMessages[0];

            m_clientSecureChannel.DecryptApplicationMessage(cipherMessage);
            cipherMessage = new NetMQMessage(cipherMessageCopy);

            result = m_clientSecureChannel.ResolveRecordLayer(cipherMessage.First.Buffer, out offset, out sslMessages);

            Assert.AreEqual(sslMessages.Count, 1);
            cipherMessage = sslMessages[0];

            NetMQSecurityException exception = Assert.Throws<NetMQSecurityException>(() => m_clientSecureChannel.DecryptApplicationMessage(cipherMessage));

            Assert.AreEqual(NetMQSecurityErrorCode.MACNotMatched, exception.ErrorCode);
        }

        [Test]
        public void DecryptingOldMessage()
        {
            NetMQMessage plainMessage = new NetMQMessage();

            NetMQMessage cipherMessageCopy = m_serverSecureChannel.EncryptApplicationMessage(plainMessage);

            NetMQMessage cipherMessage = new NetMQMessage(cipherMessageCopy);
            // copy of the first message, we are actually never try to decrypt the first message 
            // (to make sure the exception is because of the old message and not because the message was decrypted twice).


            // the window size is 1024, we to decrypt 1024 messages before trying to decrypt the old message
            bool changeCipherSepc = m_serverSecureChannel.ChangeSuiteChangeArrived;
            int offset;
            List<NetMQMessage> sslMessages;
            for (int i = 0; i < 1025; i++)
            {
                m_clientSecureChannel.ResolveRecordLayer(cipherMessage.First.Buffer, out offset, out sslMessages);
                Assert.AreEqual(sslMessages.Count, 1);
                cipherMessage = sslMessages[0];
                m_clientSecureChannel.DecryptApplicationMessage(cipherMessage);
                cipherMessage = m_serverSecureChannel.EncryptApplicationMessage(plainMessage);
            }
            cipherMessage = cipherMessageCopy;

            bool result = m_clientSecureChannel.ResolveRecordLayer(cipherMessage.First.Buffer, out offset, out sslMessages);

            Assert.AreEqual(sslMessages.Count, 1);
            cipherMessage = sslMessages[0];
            NetMQSecurityException exception = Assert.Throws<NetMQSecurityException>(() => m_clientSecureChannel.DecryptApplicationMessage(cipherMessage));

            Assert.AreEqual(NetMQSecurityErrorCode.MACNotMatched, exception.ErrorCode);
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

            int offset;
            List<NetMQMessage> sslMessages;
            bool result = m_serverSecureChannel.ResolveRecordLayer(cipher1.First.Buffer, out offset, out sslMessages);

            Assert.AreEqual(sslMessages.Count, 1);
            cipher1 = sslMessages[0];
            result = m_serverSecureChannel.ResolveRecordLayer(cipher2.First.Buffer, out offset, out sslMessages);
            Assert.AreEqual(sslMessages.Count, 1);
            cipher2 = sslMessages[0];

            NetMQSecurityException exception = Assert.Throws<NetMQSecurityException>(() => m_serverSecureChannel.DecryptApplicationMessage(cipher2));

            Assert.AreEqual(NetMQSecurityErrorCode.MACNotMatched, exception.ErrorCode);
            exception = Assert.Throws<NetMQSecurityException>(() => m_serverSecureChannel.DecryptApplicationMessage(cipher1));

            Assert.AreEqual(NetMQSecurityErrorCode.MACNotMatched, exception.ErrorCode);
        }
    }
}
