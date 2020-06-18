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
using NetMQ.Security.TLS12.Layer;
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

            List<RecordLayer> outClientHandShakeLayers = new List<RecordLayer>();
            List<RecordLayer> outserverHandShakeLayers = new List<RecordLayer>();

            bool serverComplete = false;

            bool clientComplete = m_clientSecureChannel.ProcessMessage(null, outClientHandShakeLayers);

            while (!serverComplete || !clientComplete)
            {
                if (!serverComplete)
                {
                    foreach (var message in outClientHandShakeLayers)
                    {
                        serverComplete = m_serverSecureChannel.ProcessMessage(message, outserverHandShakeLayers);

                        if (serverComplete)
                        {
                            break;
                        }
                    }

                    outClientHandShakeLayers.Clear();
                }

                if (!clientComplete)
                {
                    foreach (var message in outserverHandShakeLayers)
                    {
                        clientComplete = m_clientSecureChannel.ProcessMessage(message, outClientHandShakeLayers);

                        if (clientComplete)
                        {
                            break;
                        }
                    }

                    outserverHandShakeLayers.Clear();
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
        public void SessionRecoverTest()
        {
            Configuration configuration = new Configuration(){ VerifyCertificate = false };
            X509Certificate2 certificate = new X509Certificate2(NUnit.Framework.TestContext.CurrentContext.TestDirectory + "\\server.pfx", "1234");
            byte []sessionId = Encoding.ASCII.GetBytes(Guid.NewGuid().ToString("N"));
            SecureChannel serverSecureChannel = SecureChannel.CreateServerSecureChannel(configuration);
            serverSecureChannel.Certificate = certificate;

            SecureChannel clientSecureChannel = SecureChannel.CreateClientSecureChannel(sessionId, configuration);

            List<RecordLayer> outClientHandShakeLayers = new List<RecordLayer>();
            List<RecordLayer> outserverHandShakeLayers = new List<RecordLayer>();

            bool serverComplete = false;

            bool clientComplete = clientSecureChannel.ProcessMessage(null, outClientHandShakeLayers);

            Assert.IsTrue(clientSecureChannel.SessionId.SequenceEqual(sessionId));
            while (!serverComplete || !clientComplete)
            {
                if (!serverComplete)
                {
                    foreach (var message in outClientHandShakeLayers)
                    {
                        serverComplete = serverSecureChannel.ProcessMessage(message, outserverHandShakeLayers);

                        Assert.IsTrue(serverSecureChannel.SessionId.SequenceEqual(sessionId));
                        if (serverComplete)
                        {
                            break;
                        }
                    }

                }

                outClientHandShakeLayers.Clear();
                if (!clientComplete)
                {
                    foreach (var message in outserverHandShakeLayers)
                    {
                        clientComplete = clientSecureChannel.ProcessMessage(message, outClientHandShakeLayers);

                        Assert.IsTrue(clientSecureChannel.SessionId.SequenceEqual(sessionId));
                        if (clientComplete)
                        {
                            break;
                        }
                    }
                }
                outserverHandShakeLayers.Clear();
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
            List<RecordLayer> outClientHandShakeLayers = new List<RecordLayer>();
            List<RecordLayer> outserverHandShakeLayers = new List<RecordLayer>();

            bool clientComplete = clientSecureChannel.ProcessMessage(null, outClientHandShakeLayers);
            bool serverComplete = false;
            foreach (var message in outClientHandShakeLayers)
            {
                serverComplete = serverSecureChannel.ProcessMessage(message, outserverHandShakeLayers);

                Assert.IsTrue(serverSecureChannel.SessionId.SequenceEqual(sessionId));
                if (serverComplete)
                {
                    break;
                }
            }
            var alertMessage = serverSecureChannel.CreateAlert(AlertLevel.Warning, AlertDescription.DecryptError);
            AlertProtocol alert = alertMessage.RecordProtocols[0] as AlertProtocol;
            Assert.IsNotNull(alert);
            Assert.AreEqual(alert.Level, AlertLevel.Warning);
            Assert.AreEqual(alert.Description, AlertDescription.DecryptError);

            List<RecordLayer> recordLayers = new List<RecordLayer>();
            outClientHandShakeLayers.Clear();
            bool result = clientSecureChannel.ResolveRecordLayer(new ReadonlyBuffer<byte>(alertMessage), recordLayers, outClientHandShakeLayers);
            alertMessage = clientSecureChannel.CreateAlert(AlertLevel.Warning, AlertDescription.DecryptError);

            alert = alertMessage.RecordProtocols[0] as AlertProtocol;
            Assert.IsNotNull(alert);
            Assert.AreEqual(alert.Level, AlertLevel.Warning);
            Assert.AreEqual(alert.Description, AlertDescription.DecryptError);
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

            List<RecordLayer> outClientHandShakeLayers = new List<RecordLayer>();
            List<RecordLayer> outserverHandShakeLayers = new List<RecordLayer>();

            bool serverComplete = false;

            bool clientComplete = clientSecureChannel.ProcessMessage(null, outClientHandShakeLayers);

            while (!serverComplete || !clientComplete)
            {
                if (!serverComplete)
                {
                    foreach (var message in outClientHandShakeLayers)
                    {
                        serverComplete = serverSecureChannel.ProcessMessage(message, outserverHandShakeLayers);

                        if (serverComplete)
                        {
                            break;
                        }
                    }
                    outClientHandShakeLayers.Clear();
                }

                if (!clientComplete)
                {
                    foreach (var message in outserverHandShakeLayers)
                    {
                        clientComplete = clientSecureChannel.ProcessMessage(message, outClientHandShakeLayers);

                        if (clientComplete)
                        {
                            break;
                        }
                    }

                    outserverHandShakeLayers.Clear();
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
            List<RecordLayer> outClientHandShakeLayers = new List<RecordLayer>();
            List<RecordLayer> outserverHandShakeLayers = new List<RecordLayer>();


            bool serverComplete = false;

            bool clientComplete = clientSecureChannel.ProcessMessage(null, outClientHandShakeLayers);

            while (!serverComplete || !clientComplete)
            {
                if (!serverComplete)
                {
                    foreach (var message in outClientHandShakeLayers)
                    {
                        ReadonlyBuffer<byte> data = new ReadonlyBuffer<byte>(message);
                        serverComplete = serverSecureChannel.ResolveRecordLayer(data, null, outserverHandShakeLayers);
                        Assert.AreEqual(data.Length, 0);
                        if (serverComplete)
                        {
                            break;
                        }
                    }
                    outClientHandShakeLayers.Clear();
                }

                if (!clientComplete)
                {
                    foreach (var message in outserverHandShakeLayers)
                    {
                        ReadonlyBuffer<byte> data = new ReadonlyBuffer<byte>(message);
                        clientComplete = clientSecureChannel.ResolveRecordLayer(data, null, outClientHandShakeLayers);

                        Assert.AreEqual(0, data.Length);
                        Assert.AreEqual(data.Length, 0);
                        if (clientComplete)
                        {
                            break;
                        }
                    }

                    outserverHandShakeLayers.Clear();
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

            List<RecordLayer> outClientHandShakeLayers = new List<RecordLayer>();
            List<RecordLayer> outserverHandShakeLayers = new List<RecordLayer>();

            bool serverComplete = false;

            bool clientComplete = clientSecureChannel.ProcessMessage(null, outClientHandShakeLayers);

            while (!serverComplete || !clientComplete)
            {
                if (!serverComplete)
                {
                    int offset=0 ;
                    byte[] combineBytes = new byte[outClientHandShakeLayers.Sum(c => ((byte[])c).Length)];
                    foreach (var clientOutgoingMessage in outClientHandShakeLayers)
                    {
                        byte[] data = clientOutgoingMessage;
                        Buffer.BlockCopy(data, 0, combineBytes, offset, data.Length);
                        offset += data.Length;
                    }
                    ReadonlyBuffer<byte> buffer = new ReadonlyBuffer<byte>(combineBytes);
                    serverComplete = serverSecureChannel.ResolveRecordLayer(buffer,null, outserverHandShakeLayers);
                    Assert.AreEqual(buffer.Length , 0);
                    outClientHandShakeLayers.Clear();
                }

                if (!clientComplete)
                {
                    int offset =0;
                    byte[] combineBytes = new byte[outserverHandShakeLayers.Sum(c => ((byte[])c).Length)];
                    foreach (var clientOutgoingMessage in outserverHandShakeLayers)
                    {
                        byte[] data = clientOutgoingMessage;
                        Buffer.BlockCopy(data, 0, combineBytes, offset, data.Length);
                        offset += data.Length;
                    }
                    ReadonlyBuffer<byte> buffer = new ReadonlyBuffer<byte>(combineBytes);
                    clientComplete = clientSecureChannel.ResolveRecordLayer(buffer, null, outClientHandShakeLayers);
                    Assert.AreEqual(buffer.Length, 0);

                    outserverHandShakeLayers.Clear();
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
                var combineBytes = m_serverSecureChannel.EncryptApplicationData(buffer);
                List<RecordLayer> recordLayers = new List<RecordLayer>();
                List<RecordLayer> handshakeLayers = new List<RecordLayer>();

                ReadonlyBuffer<byte> buffer1 = new ReadonlyBuffer<byte>(combineBytes);

                bool result = m_clientSecureChannel.ResolveRecordLayer(buffer1, recordLayers, handshakeLayers);

                Assert.AreEqual(result, true);
                Assert.AreEqual(result, true);
                List<RecordLayer> plainMessageList = new List<RecordLayer>();
                foreach (var message in recordLayers)
                {
                    byte[] d = m_clientSecureChannel.DecryptApplicationData(message.RecordProtocols[0].HandShakeData);
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
            var combineBytes = m_serverSecureChannel.EncryptApplicationData(buffer);
            List<RecordLayer> recordLayers = new List<RecordLayer>();
            List<RecordLayer> handshakeLayers = new List<RecordLayer>();

            ReadonlyBuffer<byte> buffer1 = new ReadonlyBuffer<byte>(combineBytes);

            bool result = m_clientSecureChannel.ResolveRecordLayer(buffer1, recordLayers, handshakeLayers);

            Assert.AreEqual(result, true);

            Assert.AreEqual(buffer1.Length, 0);
            Assert.AreEqual(recordLayers.Count, 1);

            byte[] d = m_clientSecureChannel.DecryptApplicationData(recordLayers[0].RecordProtocols[0].HandShakeData);
            Assert.AreEqual(Encoding.GetEncoding("GBK").GetString(d), "HelloWorld");
        }

        [Test]
        public void TwoWayMessaging()
        {
            // server to client
            ReadonlyBuffer<byte> buffer = new ReadonlyBuffer<byte>(Encoding.GetEncoding("GBK").GetBytes("Hello"));
            var combineBytes = m_serverSecureChannel.EncryptApplicationData(buffer);
            List<RecordLayer> recordLayers = new List<RecordLayer>();
            List<RecordLayer> handshakeLayers = new List<RecordLayer>();
            ReadonlyBuffer<byte> buffer1 = new ReadonlyBuffer<byte>(combineBytes);

            bool result = m_clientSecureChannel.ResolveRecordLayer(buffer1, recordLayers, handshakeLayers);

            Assert.AreEqual(recordLayers.Count, 1);

            byte[] d = m_clientSecureChannel.DecryptApplicationData(recordLayers[0].RecordProtocols[0].HandShakeData);
            Assert.AreEqual(Encoding.GetEncoding("GBK").GetString(d), "Hello");

            // client to server
            buffer = new ReadonlyBuffer<byte>(Encoding.GetEncoding("GBK").GetBytes("Reply"));
            combineBytes = m_clientSecureChannel.EncryptApplicationData(buffer);
            buffer1 = new ReadonlyBuffer<byte>(combineBytes);
            recordLayers.Clear();
            result = m_serverSecureChannel.ResolveRecordLayer(buffer1, recordLayers, handshakeLayers);

            Assert.AreEqual(recordLayers.Count, 1);

            d = m_serverSecureChannel.DecryptApplicationData(recordLayers[0].RecordProtocols[0].HandShakeData);
            Assert.AreEqual(Encoding.GetEncoding("GBK").GetString(d), "Reply");
        }

        [Test]
        public void EmptyMessge()
        {
            ReadonlyBuffer<byte> buffer = new ReadonlyBuffer<byte>(EmptyArray<byte>.Instance);

            var cipherMessage = m_serverSecureChannel.EncryptApplicationData(buffer);

            List<RecordLayer> recordLayers = new List<RecordLayer>();
            List<RecordLayer> handshakeLayers = new List<RecordLayer>();


            ReadonlyBuffer<byte> buffer1 = new ReadonlyBuffer<byte>(cipherMessage);
            bool result = m_clientSecureChannel.ResolveRecordLayer(buffer1, recordLayers, handshakeLayers);

            Assert.AreEqual(recordLayers.Count, 1);
            byte[] d = m_clientSecureChannel.DecryptApplicationData(recordLayers[0].RecordProtocols[0].HandShakeData);

            Assert.AreEqual(d.Length, 0);
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

            var combineBytes = m_serverSecureChannel.EncryptApplicationData(buffer);
            List<RecordLayer> recordLayers = new List<RecordLayer>();
            List<RecordLayer> handshakeLayers = new List<RecordLayer>();

            ReadonlyBuffer<byte> buffer1 = new ReadonlyBuffer<byte>(combineBytes);

            bool result = m_clientSecureChannel.ResolveRecordLayer(buffer1, recordLayers, handshakeLayers);
            Assert.AreEqual(result, true);
            List<RecordLayer> plainMessageList = new List<RecordLayer>();
            int sum = 0;
            foreach (var message in recordLayers)
            {
                byte[] d = m_clientSecureChannel.DecryptApplicationData(message.RecordProtocols[0].HandShakeData);
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
            Queue<byte[]> queue = new Queue<byte[]>(2000);
            bool finish = false;
            for (int i = 0; i < 4; i++)
            {
                Thread thread = new Thread(() =>
                {
                    try
                    {
                        for (int j = 0; j < 500; j++)
                        {
                            byte[]  plainMessage1 = Encoding.ASCII.GetBytes("Hello");
                            lock (queue)
                            {
                                byte[] cipherMessage1 = m_serverSecureChannel.EncryptApplicationData((ReadonlyBuffer<byte>)plainMessage1);
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
                            byte[] cipherMessage1;
                            lock (queue)
                            {
                                cipherMessage1 = queue.Dequeue();
                            }
                            List<RecordLayer> recordLayers = new List<RecordLayer>();
                            List<RecordLayer> handshakeLayers = new List<RecordLayer>();
                            m_clientSecureChannel.ResolveRecordLayer((ReadonlyByteBuffer)cipherMessage1, recordLayers, handshakeLayers);

                            byte[] decryptedMessage1 = m_clientSecureChannel.DecryptApplicationData((ReadonlyByteBuffer)recordLayers[0].RecordProtocols[0].ToBytes());
                            Assert.AreEqual(Encoding.ASCII.GetString(decryptedMessage1), "Hello");
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
        public void ChangeThePadding()
        {
            byte[]  plainMessage = Encoding.ASCII.GetBytes("Hello");

            byte[] cipherMessage = m_serverSecureChannel.EncryptApplicationData((ReadonlyBuffer<byte>)plainMessage);

            List<RecordLayer> recordLayers = new List<RecordLayer>();
            List<RecordLayer> handshakeLayers = new List<RecordLayer>();

            bool result = m_clientSecureChannel.ResolveRecordLayer((ReadonlyBuffer<byte>)cipherMessage, recordLayers, handshakeLayers);


            Assert.AreEqual(recordLayers.Count, 1);
            cipherMessage = recordLayers[0].RecordProtocols[0].ToBytes();

            cipherMessage[15]++;

            NetMQSecurityException exception = Assert.Throws<NetMQSecurityException>(() => m_clientSecureChannel.DecryptApplicationData((ReadonlyBuffer<byte>)cipherMessage));

            Assert.AreEqual(NetMQSecurityErrorCode.MACNotMatched, exception.ErrorCode);
        }

        [Test]
        public void ReplayAttach()
        {
            byte[] plainMessage = EmptyArray<byte>.Instance;

            byte[] cipherMessage = m_serverSecureChannel.EncryptApplicationData((ReadonlyBuffer<byte>)plainMessage);

            byte[] cipherMessageCopy = cipherMessage.ToArray();
            List<RecordLayer> recordLayers = new List<RecordLayer>();
            List<RecordLayer> handshakeLayers = new List<RecordLayer>();

            bool result = m_clientSecureChannel.ResolveRecordLayer((ReadonlyBuffer<byte>)cipherMessage, recordLayers, handshakeLayers);

            Assert.AreEqual(recordLayers.Count, 1);
            cipherMessage = recordLayers[0].RecordProtocols[0].ToBytes();

            m_clientSecureChannel.DecryptApplicationData((ReadonlyBuffer<byte>)cipherMessage);
            cipherMessage = cipherMessageCopy;
            recordLayers.Clear();
            result = m_clientSecureChannel.ResolveRecordLayer((ReadonlyBuffer<byte>)cipherMessage, recordLayers, handshakeLayers);

            Assert.AreEqual(recordLayers.Count, 1);
            cipherMessage = recordLayers[0].RecordProtocols[0].ToBytes();

            NetMQSecurityException exception = Assert.Throws<NetMQSecurityException>(() => m_clientSecureChannel.DecryptApplicationData((ReadonlyBuffer<byte>)cipherMessage));

            Assert.AreEqual(NetMQSecurityErrorCode.MACNotMatched, exception.ErrorCode);
        }
        [Test]
        public void DecryptOutOfOrder()
        {
            byte[] plain1 = Encoding.ASCII.GetBytes("1");

            byte[] plain2 = Encoding.ASCII.GetBytes("2");

            byte[] cipher1 = m_clientSecureChannel.EncryptApplicationData((ReadonlyBuffer<byte>)plain1);
            byte[] cipher2 = m_clientSecureChannel.EncryptApplicationData((ReadonlyBuffer<byte>)plain2);

            List<RecordLayer> recordLayers1 = new List<RecordLayer>();

            List<RecordLayer> handshakeLayers = new List<RecordLayer>();
            bool result = m_serverSecureChannel.ResolveRecordLayer((ReadonlyBuffer<byte>)cipher1, recordLayers1, handshakeLayers);

            Assert.AreEqual(recordLayers1.Count, 1);
            cipher1 = recordLayers1[0].RecordProtocols[0].ToBytes();
            List<RecordLayer> recordLayers2 = new List<RecordLayer>();
            result = m_serverSecureChannel.ResolveRecordLayer((ReadonlyBuffer<byte>)cipher2, recordLayers2, handshakeLayers);
            Assert.AreEqual(recordLayers2.Count, 1);
            cipher2 = recordLayers2[0].RecordProtocols[0].ToBytes();

            NetMQSecurityException exception = Assert.Throws<NetMQSecurityException>(() => m_serverSecureChannel.DecryptApplicationData((ReadonlyBuffer<byte>)cipher2));

            Assert.AreEqual(NetMQSecurityErrorCode.MACNotMatched, exception.ErrorCode);
            exception = Assert.Throws<NetMQSecurityException>(() => m_serverSecureChannel.DecryptApplicationData((ReadonlyBuffer<byte>)cipher1));

            Assert.AreEqual(NetMQSecurityErrorCode.MACNotMatched, exception.ErrorCode);
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
