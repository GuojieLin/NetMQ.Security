using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using NetMQ.Security;
using NetMQ.Security.Enums;
using NetMQ.Security.Extensions;
using NetMQ.Security.Layer;
using NetMQ.Security.TLS12;
using NUnit.Framework;

namespace NetMQ.Security.Tests
{
    [TestFixture]
    public class TLS12SecureChannelTests
    {
        private SecureChannel m_clientSecureChannel;
        private SecureChannel m_serverSecureChannel;
        [SetUp]
        public void Setup()
        {
            Configuration configuration = new Configuration(){ VerifyCertificate = false };
            X509Certificate2 certificate = new X509Certificate2(NUnit.Framework.TestContext.CurrentContext.TestDirectory + "\\server.pfx", "1234");

            m_serverSecureChannel = SecureChannel.CreateServerSecureChannel(configuration);
            m_serverSecureChannel.Certificate = certificate;

            m_clientSecureChannel = SecureChannel.CreateClientSecureChannel(null, configuration);

            List<RecordLayer> clientOutgoingMessages = new List<RecordLayer>();
            List<RecordLayer> serverOutgoingMessages = new List<RecordLayer>();

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
        public void SessionRecoverTest()
        {
            Configuration configuration = new Configuration(){ VerifyCertificate = false };
            X509Certificate2 certificate = new X509Certificate2(NUnit.Framework.TestContext.CurrentContext.TestDirectory + "\\server.pfx", "1234");
            byte []sessionId = Encoding.ASCII.GetBytes(Guid.NewGuid().ToString("N"));
            SecureChannel serverSecureChannel = SecureChannel.CreateServerSecureChannel(configuration);
            serverSecureChannel.Certificate = certificate;

            SecureChannel clientSecureChannel = SecureChannel.CreateClientSecureChannel(sessionId, configuration);

            List<RecordLayer> clientOutgoingMessages = new List<RecordLayer>();
            List<RecordLayer> serverOutgoingMessages = new List<RecordLayer>();

            bool serverComplete = false;

            bool clientComplete = clientSecureChannel.ProcessMessage(null, clientOutgoingMessages);

            Assert.IsTrue(clientSecureChannel.SessionId.SequenceEqual(sessionId));
            while (!serverComplete || !clientComplete)
            {
                if (!serverComplete)
                {
                    foreach (var message in clientOutgoingMessages)
                    {
                        serverComplete = serverSecureChannel.ProcessMessage(message, serverOutgoingMessages);

                        Assert.IsTrue(serverSecureChannel.SessionId.SequenceEqual(sessionId));
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
                        clientComplete = clientSecureChannel.ProcessMessage(message, clientOutgoingMessages);

                        Assert.IsTrue(clientSecureChannel.SessionId.SequenceEqual(sessionId));
                        if (clientComplete)
                        {
                            break;
                        }
                    }
                    serverOutgoingMessages.Clear();
                }
            }
            clientSecureChannel.Dispose();
            serverSecureChannel.Dispose();
        }

        [Test]
        public void AlertTest()
        {
            Configuration configuration = new Configuration(){ VerifyCertificate = false };
            X509Certificate2 certificate = new X509Certificate2(NUnit.Framework.TestContext.CurrentContext.TestDirectory + "\\server.pfx", "1234");
            byte []sessionId = Encoding.ASCII.GetBytes(Guid.NewGuid().ToString("N"));
            SecureChannel serverSecureChannel = SecureChannel.CreateServerSecureChannel(configuration);
            serverSecureChannel.Certificate = certificate;

            SecureChannel clientSecureChannel = SecureChannel.CreateClientSecureChannel(sessionId, configuration);
            List<RecordLayer> clientOutgoingMessages = new List<RecordLayer>();
            List<RecordLayer> serverOutgoingMessages = new List<RecordLayer>();
            bool clientComplete = clientSecureChannel.ProcessMessage(null, clientOutgoingMessages);
            bool serverComplete = false;
            foreach (var message in clientOutgoingMessages)
            {
                serverComplete = serverSecureChannel.ProcessMessage(message, serverOutgoingMessages);

                Assert.IsTrue(serverSecureChannel.SessionId.SequenceEqual(sessionId));
                if (serverComplete)
                {
                    break;
                }
            }
            var alertMessage = serverSecureChannel.Alert(AlertLevel.Warning, AlertDescription.DecryptError);
            Assert.AreEqual(alertMessage.FrameCount, 5);
            Assert.AreEqual(alertMessage.First.BufferSize, 1);
            Assert.AreEqual((int)alertMessage.First.Buffer[0], 21);
            Assert.AreEqual(alertMessage[3].BufferSize, 1);
            Assert.AreEqual((AlertLevel)alertMessage[3].Buffer[0], AlertLevel.Warning);
            Assert.AreEqual(alertMessage[4].BufferSize, 1);
            Assert.AreEqual((AlertDescription)alertMessage[4].Buffer[0], AlertDescription.DecryptError);


            byte[] combineBytes= new byte[0];
            int sum = 0;
            foreach (var frame in alertMessage)
            {
                combineBytes = combineBytes.Combine(frame.Buffer);
                sum += frame.BufferSize;
            }
            Assert.AreEqual(sum, combineBytes.Length);
            bool result = clientSecureChannel.ResolveRecordLayer(new ReadonlyBuffer<byte>(combineBytes), clientOutgoingMessages);
            alertMessage = clientSecureChannel.Alert(AlertLevel.Warning, AlertDescription.DecryptError);
            Assert.AreEqual(alertMessage.FrameCount, 5);
            Assert.AreEqual(alertMessage.First.BufferSize, 1);
            Assert.AreEqual((int)alertMessage.First.Buffer[0], 21);
            Assert.AreEqual(alertMessage[3].BufferSize, 1);
            Assert.AreEqual((AlertLevel)alertMessage[3].Buffer[0], AlertLevel.Warning);
            Assert.AreEqual(alertMessage[4].BufferSize, 1);
            Assert.AreEqual((AlertDescription)alertMessage[4].Buffer[0], AlertDescription.DecryptError);
            clientSecureChannel.Dispose();
            serverSecureChannel.Dispose();
        }
        [Test]
        public void HandShakeTest()
        {
            Configuration configuration = new Configuration(){ VerifyCertificate = false };
            X509Certificate2 certificate = new X509Certificate2(NUnit.Framework.TestContext.CurrentContext.TestDirectory + "\\server.pfx", "1234");

            SecureChannel serverSecureChannel = SecureChannel.CreateServerSecureChannel(configuration);
            serverSecureChannel.Certificate = certificate ;

            SecureChannel clientSecureChannel = SecureChannel.CreateClientSecureChannel(null, configuration);

            List<RecordLayer> clientOutgoingMessages = new List<RecordLayer>();
            List<RecordLayer> serverOutgoingMessages = new List<RecordLayer>();

            bool serverComplete = false;

            bool clientComplete = clientSecureChannel.ProcessMessage(null, clientOutgoingMessages);

            while (!serverComplete || !clientComplete)
            {
                if (!serverComplete)
                {
                    foreach (var message in clientOutgoingMessages)
                    {
                        serverComplete = serverSecureChannel.ProcessMessage(message, serverOutgoingMessages);

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
                        clientComplete = clientSecureChannel.ProcessMessage(message, clientOutgoingMessages);

                        if (clientComplete)
                        {
                            break;
                        }
                    }

                    serverOutgoingMessages.Clear();
                }
            }
            clientSecureChannel.Dispose();
            serverSecureChannel.Dispose();
        }
        [Test]
        public void AES128SHAHandShakeTest()
        {
            Configuration configuration = new Configuration() { VerifyCertificate = false };
            X509Certificate2 certificate = new X509Certificate2(NUnit.Framework.TestContext.CurrentContext.TestDirectory + "\\server.pfx", "1234");

            SecureChannel serverSecureChannel = SecureChannel.CreateServerSecureChannel(configuration);
            serverSecureChannel.Certificate = certificate;

            SecureChannel clientSecureChannel = SecureChannel.CreateClientSecureChannel(null, configuration);
            clientSecureChannel.AllowedCipherSuites = new[] { CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA };
            List<RecordLayer> clientOutgoingMessages = new List<RecordLayer>();
            List<RecordLayer> serverOutgoingMessages = new List<RecordLayer>();


            bool serverComplete = false;

            bool clientComplete = clientSecureChannel.ProcessMessage(null, clientOutgoingMessages);

            while (!serverComplete || !clientComplete)
            {
                if (!serverComplete)
                {
                    foreach (var message in clientOutgoingMessages)
                    {
                        ReadonlyBuffer<byte> data = new ReadonlyBuffer<byte>(message);
                        serverComplete = serverSecureChannel.ResolveRecordLayer(data, serverOutgoingMessages);
                        Assert.AreEqual(data.Length, 0);
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
                        ReadonlyBuffer<byte> data = new ReadonlyBuffer<byte>(message);
                        clientComplete = clientSecureChannel.ResolveRecordLayer(data, clientOutgoingMessages);

                        Assert.AreEqual(0, data.Length);
                        Assert.AreEqual(data.Length, 0);
                        if (clientComplete)
                        {
                            break;
                        }
                    }

                    serverOutgoingMessages.Clear();
                }
            }
            clientSecureChannel.Dispose();
            serverSecureChannel.Dispose();
        }
        [Test]
        public void HandShakePacketSplicingTest()
        {
            Configuration configuration = new Configuration() { VerifyCertificate = false };
            X509Certificate2 certificate = new X509Certificate2(NUnit.Framework.TestContext.CurrentContext.TestDirectory + "\\server.pfx", "1234");

            SecureChannel serverSecureChannel = SecureChannel.CreateServerSecureChannel(configuration);
            serverSecureChannel.Certificate = certificate;

            SecureChannel clientSecureChannel = SecureChannel.CreateClientSecureChannel(null, configuration);

            List<RecordLayer> clientOutgoingMessages = new List<RecordLayer>();
            List<RecordLayer> serverOutgoingMessages = new List<RecordLayer>();

            bool serverComplete = false;

            bool clientComplete = clientSecureChannel.ProcessMessage(null, clientOutgoingMessages);

            while (!serverComplete || !clientComplete)
            {
                if (!serverComplete)
                {
                    int offset=0 ;
                    byte[] combineBytes = new byte[clientOutgoingMessages.Sum(c => ((byte[])c).Length)];
                    foreach (var clientOutgoingMessage in clientOutgoingMessages)
                    {
                        byte[] data = clientOutgoingMessage;
                        Buffer.BlockCopy(data, 0, combineBytes, offset, data.Length);
                        offset += data.Length;
                    }
                    ReadonlyBuffer<byte> buffer = new ReadonlyBuffer<byte>(combineBytes);
                    serverComplete = serverSecureChannel.ResolveRecordLayer(buffer, serverOutgoingMessages);
                    Assert.AreEqual(buffer.Length , 0);
                    clientOutgoingMessages.Clear();
                }

                if (!clientComplete)
                {
                    int offset =0;
                    byte[] combineBytes = new byte[serverOutgoingMessages.Sum(c => ((byte[])c).Length)];
                    foreach (var clientOutgoingMessage in serverOutgoingMessages)
                    {
                        byte[] data = clientOutgoingMessage;
                        Buffer.BlockCopy(data, 0, combineBytes, offset, data.Length);
                        offset += data.Length;
                    }
                    ReadonlyBuffer<byte> buffer = new ReadonlyBuffer<byte>(combineBytes);
                    clientComplete = clientSecureChannel.ResolveRecordLayer(buffer, clientOutgoingMessages);
                    Assert.AreEqual(buffer.Length, 0);

                    serverOutgoingMessages.Clear();
                }
            }
            clientSecureChannel.Dispose();
            serverSecureChannel.Dispose();
        }
        private static string str = "10009<Root><Head><CommandCode>10009</CommandCode><TransSeqID>201709081726360</TransSeqID><VerifyCode>R+Fo9QDXJKGE8h51nDl6Nrst/LjO59CKRrNbqHq8Q8Afct0zD6BQQVuuJ7CMdE1+3LegwgvXE351r0m5qyCl1RY3XTB1Mnu5IzsmloeXbaha9v3P0aVYgWL6GAc/rD6Kiemu4VjptwZb+O81pBY8OVtCyRZjCfC4NKXDVBlbMdA=</VerifyCode><ZipType></ZipType><CorpBankCode>103</CorpBankCode><FGCommandCode>11121</FGCommandCode><EnterpriseNum>QT330001</EnterpriseNum><FGVerifyCode>PYZjVNxLyNcRTP1A5EC0YC/Ogk7SHA8ZPeMx9Px0nxReyPKDfdGGzGwyZB5usAzlbFK/JB976z+S0wEp6SuP/1VZnUN4ZkDH+kbY2qnquD8RXSxrWmmOHlPIh9cJQGRvls1mrJQpti1FvJmeGDwdaLxdu+TLkr51LEpwZuQq6tQ=</FGVerifyCode></Head><RealTimeSingleTransReq><MoneyWay>1</MoneyWay><TransDate>20170908</TransDate><Trans><TransNo>BR1726360000131759</TransNo><ProtocolCode></ProtocolCode><EnterpriseAccNum>103330101</EnterpriseAccNum><CustBankCode>103</CustBankCode><CustAccNum>1031234567890000000</CustAccNum><CustAccName>农行</CustAccName><AreaCode></AreaCode><BankLocationCode></BankLocationCode><BankLocationName></BankLocationName><CardType></CardType><IsPrivate></IsPrivate><IsUrgent></IsUrgent><Amount>1.00</Amount><Currency>CNY</Currency><CertType>0</CertType><CertNum></CertNum><Mobile></Mobile><Purpose>省道测试是否的腹</Purpose><Memo>备注路口见到否</Memo><PolicyNumber></PolicyNumber><Extent1></Extent1><Extent2></Extent2><SourceTransNo>SO1726360000111307</SourceTransNo></Trans></RealTimeSingleTransReq></Root>"+"10009<Root><Head><CommandCode>10009</CommandCode><TransSeqID>201709081726360</TransSeqID><VerifyCode>R+Fo9QDXJKGE8h51nDl6Nrst/LjO59CKRrNbqHq8Q8Afct0zD6BQQVuuJ7CMdE1+3LegwgvXE351r0m5qyCl1RY3XTB1Mnu5IzsmloeXbaha9v3P0aVYgWL6GAc/rD6Kiemu4VjptwZb+O81pBY8OVtCyRZjCfC4NKXDVBlbMdA=</VerifyCode><ZipType></ZipType><CorpBankCode>103</CorpBankCode><FGCommandCode>11121</FGCommandCode><EnterpriseNum>QT330001</EnterpriseNum><FGVerifyCode>PYZjVNxLyNcRTP1A5EC0YC/Ogk7SHA8ZPeMx9Px0nxReyPKDfdGGzGwyZB5usAzlbFK/JB976z+S0wEp6SuP/1VZnUN4ZkDH+kbY2qnquD8RXSxrWmmOHlPIh9cJQGRvls1mrJQpti1FvJmeGDwdaLxdu+TLkr51LEpwZuQq6tQ=</FGVerifyCode></Head><RealTimeSingleTransReq><MoneyWay>1</MoneyWay><TransDate>20170908</TransDate><Trans><TransNo>BR1726360000131759</TransNo><ProtocolCode></ProtocolCode><EnterpriseAccNum>103330101</EnterpriseAccNum><CustBankCode>103</CustBankCode><CustAccNum>1031234567890000000</CustAccNum><CustAccName>农行</CustAccName><AreaCode></AreaCode><BankLocationCode></BankLocationCode><BankLocationName></BankLocationName><CardType></CardType><IsPrivate></IsPrivate><IsUrgent></IsUrgent><Amount>1.00</Amount><Currency>CNY</Currency><CertType>0</CertType><CertNum></CertNum><Mobile></Mobile><Purpose>省道测试是否的腹</Purpose><Memo>备注路口见到否</Memo><PolicyNumber></PolicyNumber><Extent1></Extent1><Extent2></Extent2><SourceTransNo>SO1726360000111307</SourceTransNo></Trans></RealTimeSingleTransReq></Root>"+"10009<Root><Head><CommandCode>10009</CommandCode><TransSeqID>201709081726360</TransSeqID><VerifyCode>R+Fo9QDXJKGE8h51nDl6Nrst/LjO59CKRrNbqHq8Q8Afct0zD6BQQVuuJ7CMdE1+3LegwgvXE351r0m5qyCl1RY3XTB1Mnu5IzsmloeXbaha9v3P0aVYgWL6GAc/rD6Kiemu4VjptwZb+O81pBY8OVtCyRZjCfC4NKXDVBlbMdA=</VerifyCode><ZipType></ZipType><CorpBankCode>103</CorpBankCode><FGCommandCode>11121</FGCommandCode><EnterpriseNum>QT330001</EnterpriseNum><FGVerifyCode>PYZjVNxLyNcRTP1A5EC0YC/Ogk7SHA8ZPeMx9Px0nxReyPKDfdGGzGwyZB5usAzlbFK/JB976z+S0wEp6SuP/1VZnUN4ZkDH+kbY2qnquD8RXSxrWmmOHlPIh9cJQGRvls1mrJQpti1FvJmeGDwdaLxdu+TLkr51LEpwZuQq6tQ=</FGVerifyCode></Head><RealTimeSingleTransReq><MoneyWay>1</MoneyWay><TransDate>20170908</TransDate><Trans><TransNo>BR1726360000131759</TransNo><ProtocolCode></ProtocolCode><EnterpriseAccNum>103330101</EnterpriseAccNum><CustBankCode>103</CustBankCode><CustAccNum>1031234567890000000</CustAccNum><CustAccName>农行</CustAccName><AreaCode></AreaCode><BankLocationCode></BankLocationCode><BankLocationName></BankLocationName><CardType></CardType><IsPrivate></IsPrivate><IsUrgent></IsUrgent><Amount>1.00</Amount><Currency>CNY</Currency><CertType>0</CertType><CertNum></CertNum><Mobile></Mobile><Purpose>省道测试是否的腹</Purpose><Memo>备注路口见到否</Memo><PolicyNumber></PolicyNumber><Extent1></Extent1><Extent2></Extent2><SourceTransNo>SO1726360000111307</SourceTransNo></Trans></RealTimeSingleTransReq></Root>"+"10009<Root><Head><CommandCode>10009</CommandCode><TransSeqID>201709081726360</TransSeqID><VerifyCode>R+Fo9QDXJKGE8h51nDl6Nrst/LjO59CKRrNbqHq8Q8Afct0zD6BQQVuuJ7CMdE1+3LegwgvXE351r0m5qyCl1RY3XTB1Mnu5IzsmloeXbaha9v3P0aVYgWL6GAc/rD6Kiemu4VjptwZb+O81pBY8OVtCyRZjCfC4NKXDVBlbMdA=</VerifyCode><ZipType></ZipType><CorpBankCode>103</CorpBankCode><FGCommandCode>11121</FGCommandCode><EnterpriseNum>QT330001</EnterpriseNum><FGVerifyCode>PYZjVNxLyNcRTP1A5EC0YC/Ogk7SHA8ZPeMx9Px0nxReyPKDfdGGzGwyZB5usAzlbFK/JB976z+S0wEp6SuP/1VZnUN4ZkDH+kbY2qnquD8RXSxrWmmOHlPIh9cJQGRvls1mrJQpti1FvJmeGDwdaLxdu+TLkr51LEpwZuQq6tQ=</FGVerifyCode></Head><RealTimeSingleTransReq><MoneyWay>1</MoneyWay><TransDate>20170908</TransDate><Trans><TransNo>BR1726360000131759</TransNo><ProtocolCode></ProtocolCode><EnterpriseAccNum>103330101</EnterpriseAccNum><CustBankCode>103</CustBankCode><CustAccNum>1031234567890000000</CustAccNum><CustAccName>农行</CustAccName><AreaCode></AreaCode><BankLocationCode></BankLocationCode><BankLocationName></BankLocationName><CardType></CardType><IsPrivate></IsPrivate><IsUrgent></IsUrgent><Amount>1.00</Amount><Currency>CNY</Currency><CertType>0</CertType><CertNum></CertNum><Mobile></Mobile><Purpose>省道测试是否的腹</Purpose><Memo>备注路口见到否</Memo><PolicyNumber></PolicyNumber><Extent1></Extent1><Extent2></Extent2><SourceTransNo>SO1726360000111307</SourceTransNo></Trans></RealTimeSingleTransReq></Root>";
        private static byte[] data = Encoding.GetEncoding("GBK").GetBytes(str);
        [Test]
        public void MutiBytesData()
        {
            for (int i = 0; i < 100; i++)
            {
                ReadonlyBuffer<byte> buffer = new ReadonlyBuffer<byte>(data);
                List<RecordLayer> cipherMessage = m_serverSecureChannel.EncryptApplicationData(buffer);
                var combineBytes =ToBytes(cipherMessage);
                List<RecordLayer> sslMessages = new List<RecordLayer>();

                ReadonlyBuffer<byte> buffer1 = new ReadonlyBuffer<byte>(combineBytes);

                bool result = m_clientSecureChannel.ResolveRecordLayer(buffer1, sslMessages);

                Assert.AreEqual(result, true);
                Assert.AreEqual(result, true);
                List<RecordLayer> plainMessageList = new List<RecordLayer>();
                foreach (var message in sslMessages)
                {
                    byte[] d = m_clientSecureChannel.DecryptApplicationMessage(message.RecordProtocols[0].HandShakeData);
                    Assert.AreEqual(data, d);
                }
            }
        }
        public static byte[] ToBytes(List<RecordLayer> message)
        {
            byte[] data = new byte[message.Sum(f => ((byte[])f).Length)];
            int offset = 0;
            foreach (var frame in message)
            {
                byte[] d = frame;
                Buffer.BlockCopy(d, 0, data, offset, d.Length);
                offset += d.Length;
            }
            return data;
        }
        [Test]
        public void ClientToServer()
        {
            ReadonlyBuffer<byte> buffer = new ReadonlyBuffer<byte>(Encoding.GetEncoding("GBK").GetBytes("HelloWorld"));
            List<RecordLayer> cipherMessage = m_serverSecureChannel.EncryptApplicationData(buffer);
            var combineBytes = ToBytes(cipherMessage);
            List<RecordLayer> sslMessages = new List<RecordLayer>();

            ReadonlyBuffer<byte> buffer1 = new ReadonlyBuffer<byte>(combineBytes);

            bool result = m_clientSecureChannel.ResolveRecordLayer(buffer1, sslMessages);

            Assert.AreEqual(result, true);

            Assert.AreEqual(buffer1.Length, 0);
            Assert.AreEqual(sslMessages.Count, 1);

            byte[] d = m_clientSecureChannel.DecryptApplicationMessage(sslMessages[0].RecordProtocols[0].HandShakeData);
            Assert.AreEqual(Encoding.GetEncoding("GBK").GetString(d), "HelloWorld");
        }

        [Test]
        public void TwoWayMessaging()
        {
            // server to client
            ReadonlyBuffer<byte> buffer = new ReadonlyBuffer<byte>(Encoding.GetEncoding("GBK").GetBytes("Hello"));
            List<RecordLayer> cipherMessage = m_serverSecureChannel.EncryptApplicationData(buffer);
            List<RecordLayer> sslMessages = new List<RecordLayer>();

            ReadonlyBuffer<byte> buffer1 = new ReadonlyBuffer<byte>(cipherMessage[0]);

            bool result = m_clientSecureChannel.ResolveRecordLayer(buffer1, sslMessages);

            Assert.AreEqual(sslMessages.Count, 1);

            byte[] d = m_clientSecureChannel.DecryptApplicationMessage(sslMessages[0].RecordProtocols[0].HandShakeData);
            Assert.AreEqual(Encoding.GetEncoding("GBK").GetString(d), "Hello");

            // client to server
            buffer = new ReadonlyBuffer<byte>(Encoding.GetEncoding("GBK").GetBytes("Reply"));
            cipherMessage = m_clientSecureChannel.EncryptApplicationData(buffer);
            buffer1 = new ReadonlyBuffer<byte>(cipherMessage[0]);
            sslMessages.Clear();
            result = m_serverSecureChannel.ResolveRecordLayer(buffer1, sslMessages);

            Assert.AreEqual(sslMessages.Count, 1);

            d = m_serverSecureChannel.DecryptApplicationMessage(sslMessages[0].RecordProtocols[0].HandShakeData);
            Assert.AreEqual(Encoding.GetEncoding("GBK").GetString(d), "Reply");
        }

        [Test]
        public void EmptyMessge()
        {
            ReadonlyBuffer<byte> buffer = new ReadonlyBuffer<byte>(EmptyArray<byte>.Instance);

            List<RecordLayer> cipherMessage = m_serverSecureChannel.EncryptApplicationData(buffer);

            List<RecordLayer> sslMessages = new List<RecordLayer>();


            ReadonlyBuffer<byte> buffer1 = new ReadonlyBuffer<byte>(cipherMessage[0]);
            bool result = m_clientSecureChannel.ResolveRecordLayer(buffer1, sslMessages);

            Assert.AreEqual(sslMessages.Count, 1);
            byte[] d = m_clientSecureChannel.DecryptApplicationMessage(sslMessages[0].RecordProtocols[0].HandShakeData);

            Assert.AreEqual(d.Length, 0);
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
            while (cipherMessage.FrameCount > 4)
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


        [TestCase(1)]
        [TestCase(1024)]
        [TestCase(18432)]
        [TestCase(18433)]
        [TestCase(65535)]
        [TestCase(1048576)]
        public void BigBytesData(int length)
        {
            ReadonlyBuffer<byte> buffer = new ReadonlyBuffer<byte>(new byte[length]);
            new Random().NextBytes(buffer._Data);

            List<RecordLayer> cipherMessage = m_serverSecureChannel.EncryptApplicationData(buffer);
            var combineBytes = ToBytes(cipherMessage);
            List<RecordLayer> sslMessages = new List<RecordLayer>();

            ReadonlyBuffer<byte> buffer1 = new ReadonlyBuffer<byte>(combineBytes);

            bool result = m_clientSecureChannel.ResolveRecordLayer(buffer1, sslMessages);
            Assert.AreEqual(result, true);
            List<RecordLayer> plainMessageList = new List<RecordLayer>();
            int sum = 0;
            foreach (var message in sslMessages)
            {
                byte[] d = m_clientSecureChannel.DecryptApplicationMessage(message.RecordProtocols[0].HandShakeData);
                sum += d.Length;
            }
            Assert.AreEqual(sum, buffer.Limit);
        }
        [Test]
        public void MutiThreadEncryptDecrypt()
        {
            AutoResetEvent autoResetEvent = new AutoResetEvent(false);
            int count = 0;
            object lockObject = new object();
            Queue<NetMQMessage> queue = new Queue<NetMQMessage>(2000);
            bool finish = false;
            for (int i = 0; i < 4; i++)
            {
                Thread thread = new Thread(() =>
                {
                    try
                    {
                        for (int j = 0; j < 500; j++)
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

                thread = new Thread(() =>
                {
                    try
                    {
                        while (!finish)
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
        public void AES256Test()
        {
            int FixedIVLength = 0;
            int EncKeyLength = 32;
            int BlockLength = 16;
            int RecordIVLength = 16;
            SymmetricAlgorithm encryptionBulkAlgorithm  = new AesCryptoServiceProvider
            {
                Padding = PaddingMode.None,
                KeySize = EncKeyLength * 8,
                BlockSize = BlockLength * 8
            };
            SymmetricAlgorithm decryptionBulkAlgorithm  = new AesCryptoServiceProvider
            {
                Padding = PaddingMode.None,
                KeySize = EncKeyLength * 8,
                BlockSize = BlockLength * 8
            };
        }

        /// <summary>

        /// AES加密

        /// </summary>

        /// <param name="encryptStr">明文</param>

        /// <param name="key">密钥</param>

        /// <returns></returns>

        public static string Encrypt(string encryptStr, string key)

        {

            byte[] keyArray = Encoding.UTF8.GetBytes(key);

            byte[] toEncryptArray = Encoding.UTF8.GetBytes(encryptStr);

            RijndaelManaged rDel = new RijndaelManaged();

            rDel.Key = keyArray;

            rDel.Mode = CipherMode.ECB;

            rDel.Padding = PaddingMode.PKCS7;

            ICryptoTransform cTransform = rDel.CreateEncryptor();

            byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);

            return Convert.ToBase64String(resultArray, 0, resultArray.Length);

        }


        /// <summary>

        /// AES解密

        /// </summary>

        /// <param name="decryptStr">密文</param>

        /// <param name="key">密钥</param>

        /// <returns></returns>

        public static string Decrypt(string decryptStr, string key)

        {

            byte[] keyArray = UTF8Encoding.UTF8.GetBytes(key);

            byte[] toEncryptArray = Convert.FromBase64String(decryptStr);

            RijndaelManaged rDel = new RijndaelManaged();

            rDel.Key = keyArray;

            rDel.Mode = CipherMode.ECB;

            rDel.Padding = PaddingMode.PKCS7;

            ICryptoTransform cTransform = rDel.CreateDecryptor();

            byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);

            return UTF8Encoding.UTF8.GetString(resultArray);

        }
    }
}
