using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using NetMQ.Security;
using NetMQ.Security.V0_1;
using NUnit.Framework;

namespace NetMQ.Security.Tests
{
    [TestFixture]
    public class V3_3SecureChannelFormatTests
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
        [TestCase(1)]
        [TestCase(256)]
        [TestCase(65536)]
        [TestCase(16777216)]
        public void LengthTest1(int length)
        {
            NetMQMessage message = new NetMQMessage();
            message.Append(new byte[length]);
            byte[] lengthBytes = new byte[4];
            message.GetLength(lengthBytes);
            int index=-1;
            while (length > 0)
            {
                length = length / 256;
                index++;
            }
            for (int i = 0; i < lengthBytes.Length; i++)
            {
                Assert.AreEqual(lengthBytes[i], i == 3 - index ? 1 : 0);
            }
        }
        [Test]
        [TestCase(1)]
        [TestCase(256)]
        [TestCase(65536)]
        public void LengthTest2(int length)
        {
            NetMQMessage message = new NetMQMessage();
            message.Append(new byte[length]);
            byte[] lengthBytes = new byte[3];
            message.GetLength(lengthBytes);
            int index=-1;
            while (length > 0)
            {
                length = length / 256;
                index++;
            }
            for (int i = 0; i < lengthBytes.Length; i++)
            {
                Assert.AreEqual(lengthBytes[i], i == 2 - index ? 1 : 0);
            }
        }
        [Test]
        [TestCase(1)]
        [TestCase(256)]
        public void LengthTest3(int length)
        {
            NetMQMessage message = new NetMQMessage();
            message.Append(new byte[length]);
            byte[] lengthBytes = new byte[2];
            message.GetLength(lengthBytes);
            int index=-1;
            while (length > 0)
            {
                length = length / 256;
                index++;
            }
            for (int i = 0; i < lengthBytes.Length; i++)
            {
                Assert.AreEqual(lengthBytes[i], i == 1 - index ? 1 : 0);
            }
        }

        [Test]
        public void HandShakeTest()
        {
            Configuration configuration = new Configuration(){ VerifyCertificate = false, StandardTLSFormat = true };
            X509Certificate2 certificate = new X509Certificate2(NUnit.Framework.TestContext.CurrentContext.TestDirectory + "\\server.pfx", "1234");

            m_serverSecureChannel = new SecureChannel(ConnectionEnd.Server, configuration) { Certificate = certificate };

            m_clientSecureChannel = new SecureChannel(ConnectionEnd.Client, configuration);

            IList<NetMQMessage> clientOutgoingMessages = new List<NetMQMessage>();
            IList<NetMQMessage> serverOutgoingMessages = new List<NetMQMessage>();

            bool serverComplete = false;

            bool clientComplete = m_clientSecureChannel.ProcessMessage(null, clientOutgoingMessages);

            bool serverChangeCipherSpec = false;
            bool clientChangeCipherSpec = false;
            while (!serverComplete || !clientComplete)
            {
                if (!serverComplete)
                {
                    byte[] combineBytes= new byte[0];
                    int sum = 0;
                    foreach (var message in clientOutgoingMessages)
                    {
                        foreach (var frame in message)
                        {
                            combineBytes = combineBytes.Combine(frame.Buffer);
                            sum += frame.BufferSize;
                        }
                    }
                    List<NetMQMessage> sslMessages;
                    Assert.AreEqual(sum, combineBytes.Length);
                    bool result = combineBytes.GetV0_2RecordLayerNetMQMessage(out sslMessages,ref serverChangeCipherSpec);
                    Assert.IsTrue(result);
                    Assert.AreEqual(sslMessages.Count, clientOutgoingMessages.Count);
                    for(int i = 0; i < sslMessages.Count; i ++)
                    {
                        Assert.AreEqual(sslMessages[i].FrameCount, clientOutgoingMessages[i].FrameCount);
                        for (int j = 0; j < sslMessages[i].FrameCount; j++)
                        {
                            Assert.AreEqual(sslMessages[i][j].Buffer, clientOutgoingMessages[i][j].Buffer);
                        }
                    }
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
                    byte[] combineBytes= new byte[0];
                    int sum = 0;
                    foreach (var message in serverOutgoingMessages)
                    {
                        foreach (var frame in message)
                        {
                            combineBytes = combineBytes.Combine(frame.Buffer);
                            sum += frame.BufferSize;
                        }
                    }
                    List<NetMQMessage> sslMessages;
                    Assert.AreEqual(sum, combineBytes.Length);
                    bool result = combineBytes.GetV0_2RecordLayerNetMQMessage(out sslMessages,ref clientChangeCipherSpec);
                    Assert.IsTrue(result);
                    Assert.AreEqual(sslMessages.Count, serverOutgoingMessages.Count);
                    for (int i = 0; i < sslMessages.Count; i++)
                    {
                        Assert.AreEqual(sslMessages[i].FrameCount, serverOutgoingMessages[i].FrameCount);
                        for (int j = 0; j < sslMessages[i].FrameCount; j++)
                        {
                            Assert.AreEqual(sslMessages[i][j].Buffer, serverOutgoingMessages[i][j].Buffer);
                        }
                    }
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
    }
}
