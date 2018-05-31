using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using NetMQ.Security;
using NetMQ.Security.Extensions;
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
                    int offset;
                    bool result = combineBytes.GetV0_2RecordLayerNetMQMessage(ref serverChangeCipherSpec,out offset,out sslMessages);
                    Assert.IsTrue(result);
                    Assert.AreEqual(offset, combineBytes.Length);
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
                    int offset;
                    bool result = combineBytes.GetV0_2RecordLayerNetMQMessage(ref clientChangeCipherSpec,out offset,out sslMessages);
                    Assert.AreEqual(offset, combineBytes.Length);
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

        private static string str = "10009<Root><Head><CommandCode>10009</CommandCode><TransSeqID>201709081726360</TransSeqID><VerifyCode>R+Fo9QDXJKGE8h51nDl6Nrst/LjO59CKRrNbqHq8Q8Afct0zD6BQQVuuJ7CMdE1+3LegwgvXE351r0m5qyCl1RY3XTB1Mnu5IzsmloeXbaha9v3P0aVYgWL6GAc/rD6Kiemu4VjptwZb+O81pBY8OVtCyRZjCfC4NKXDVBlbMdA=</VerifyCode><ZipType></ZipType><CorpBankCode>103</CorpBankCode><FGCommandCode>11121</FGCommandCode><EnterpriseNum>QT330001</EnterpriseNum><FGVerifyCode>PYZjVNxLyNcRTP1A5EC0YC/Ogk7SHA8ZPeMx9Px0nxReyPKDfdGGzGwyZB5usAzlbFK/JB976z+S0wEp6SuP/1VZnUN4ZkDH+kbY2qnquD8RXSxrWmmOHlPIh9cJQGRvls1mrJQpti1FvJmeGDwdaLxdu+TLkr51LEpwZuQq6tQ=</FGVerifyCode></Head><RealTimeSingleTransReq><MoneyWay>1</MoneyWay><TransDate>20170908</TransDate><Trans><TransNo>BR1726360000131759</TransNo><ProtocolCode></ProtocolCode><EnterpriseAccNum>103330101</EnterpriseAccNum><CustBankCode>103</CustBankCode><CustAccNum>1031234567890000000</CustAccNum><CustAccName>农行</CustAccName><AreaCode></AreaCode><BankLocationCode></BankLocationCode><BankLocationName></BankLocationName><CardType></CardType><IsPrivate></IsPrivate><IsUrgent></IsUrgent><Amount>1.00</Amount><Currency>CNY</Currency><CertType>0</CertType><CertNum></CertNum><Mobile></Mobile><Purpose>省道测试是否的腹</Purpose><Memo>备注路口见到否</Memo><PolicyNumber></PolicyNumber><Extent1></Extent1><Extent2></Extent2><SourceTransNo>SO1726360000111307</SourceTransNo></Trans></RealTimeSingleTransReq></Root>"+"10009<Root><Head><CommandCode>10009</CommandCode><TransSeqID>201709081726360</TransSeqID><VerifyCode>R+Fo9QDXJKGE8h51nDl6Nrst/LjO59CKRrNbqHq8Q8Afct0zD6BQQVuuJ7CMdE1+3LegwgvXE351r0m5qyCl1RY3XTB1Mnu5IzsmloeXbaha9v3P0aVYgWL6GAc/rD6Kiemu4VjptwZb+O81pBY8OVtCyRZjCfC4NKXDVBlbMdA=</VerifyCode><ZipType></ZipType><CorpBankCode>103</CorpBankCode><FGCommandCode>11121</FGCommandCode><EnterpriseNum>QT330001</EnterpriseNum><FGVerifyCode>PYZjVNxLyNcRTP1A5EC0YC/Ogk7SHA8ZPeMx9Px0nxReyPKDfdGGzGwyZB5usAzlbFK/JB976z+S0wEp6SuP/1VZnUN4ZkDH+kbY2qnquD8RXSxrWmmOHlPIh9cJQGRvls1mrJQpti1FvJmeGDwdaLxdu+TLkr51LEpwZuQq6tQ=</FGVerifyCode></Head><RealTimeSingleTransReq><MoneyWay>1</MoneyWay><TransDate>20170908</TransDate><Trans><TransNo>BR1726360000131759</TransNo><ProtocolCode></ProtocolCode><EnterpriseAccNum>103330101</EnterpriseAccNum><CustBankCode>103</CustBankCode><CustAccNum>1031234567890000000</CustAccNum><CustAccName>农行</CustAccName><AreaCode></AreaCode><BankLocationCode></BankLocationCode><BankLocationName></BankLocationName><CardType></CardType><IsPrivate></IsPrivate><IsUrgent></IsUrgent><Amount>1.00</Amount><Currency>CNY</Currency><CertType>0</CertType><CertNum></CertNum><Mobile></Mobile><Purpose>省道测试是否的腹</Purpose><Memo>备注路口见到否</Memo><PolicyNumber></PolicyNumber><Extent1></Extent1><Extent2></Extent2><SourceTransNo>SO1726360000111307</SourceTransNo></Trans></RealTimeSingleTransReq></Root>"+"10009<Root><Head><CommandCode>10009</CommandCode><TransSeqID>201709081726360</TransSeqID><VerifyCode>R+Fo9QDXJKGE8h51nDl6Nrst/LjO59CKRrNbqHq8Q8Afct0zD6BQQVuuJ7CMdE1+3LegwgvXE351r0m5qyCl1RY3XTB1Mnu5IzsmloeXbaha9v3P0aVYgWL6GAc/rD6Kiemu4VjptwZb+O81pBY8OVtCyRZjCfC4NKXDVBlbMdA=</VerifyCode><ZipType></ZipType><CorpBankCode>103</CorpBankCode><FGCommandCode>11121</FGCommandCode><EnterpriseNum>QT330001</EnterpriseNum><FGVerifyCode>PYZjVNxLyNcRTP1A5EC0YC/Ogk7SHA8ZPeMx9Px0nxReyPKDfdGGzGwyZB5usAzlbFK/JB976z+S0wEp6SuP/1VZnUN4ZkDH+kbY2qnquD8RXSxrWmmOHlPIh9cJQGRvls1mrJQpti1FvJmeGDwdaLxdu+TLkr51LEpwZuQq6tQ=</FGVerifyCode></Head><RealTimeSingleTransReq><MoneyWay>1</MoneyWay><TransDate>20170908</TransDate><Trans><TransNo>BR1726360000131759</TransNo><ProtocolCode></ProtocolCode><EnterpriseAccNum>103330101</EnterpriseAccNum><CustBankCode>103</CustBankCode><CustAccNum>1031234567890000000</CustAccNum><CustAccName>农行</CustAccName><AreaCode></AreaCode><BankLocationCode></BankLocationCode><BankLocationName></BankLocationName><CardType></CardType><IsPrivate></IsPrivate><IsUrgent></IsUrgent><Amount>1.00</Amount><Currency>CNY</Currency><CertType>0</CertType><CertNum></CertNum><Mobile></Mobile><Purpose>省道测试是否的腹</Purpose><Memo>备注路口见到否</Memo><PolicyNumber></PolicyNumber><Extent1></Extent1><Extent2></Extent2><SourceTransNo>SO1726360000111307</SourceTransNo></Trans></RealTimeSingleTransReq></Root>"+"10009<Root><Head><CommandCode>10009</CommandCode><TransSeqID>201709081726360</TransSeqID><VerifyCode>R+Fo9QDXJKGE8h51nDl6Nrst/LjO59CKRrNbqHq8Q8Afct0zD6BQQVuuJ7CMdE1+3LegwgvXE351r0m5qyCl1RY3XTB1Mnu5IzsmloeXbaha9v3P0aVYgWL6GAc/rD6Kiemu4VjptwZb+O81pBY8OVtCyRZjCfC4NKXDVBlbMdA=</VerifyCode><ZipType></ZipType><CorpBankCode>103</CorpBankCode><FGCommandCode>11121</FGCommandCode><EnterpriseNum>QT330001</EnterpriseNum><FGVerifyCode>PYZjVNxLyNcRTP1A5EC0YC/Ogk7SHA8ZPeMx9Px0nxReyPKDfdGGzGwyZB5usAzlbFK/JB976z+S0wEp6SuP/1VZnUN4ZkDH+kbY2qnquD8RXSxrWmmOHlPIh9cJQGRvls1mrJQpti1FvJmeGDwdaLxdu+TLkr51LEpwZuQq6tQ=</FGVerifyCode></Head><RealTimeSingleTransReq><MoneyWay>1</MoneyWay><TransDate>20170908</TransDate><Trans><TransNo>BR1726360000131759</TransNo><ProtocolCode></ProtocolCode><EnterpriseAccNum>103330101</EnterpriseAccNum><CustBankCode>103</CustBankCode><CustAccNum>1031234567890000000</CustAccNum><CustAccName>农行</CustAccName><AreaCode></AreaCode><BankLocationCode></BankLocationCode><BankLocationName></BankLocationName><CardType></CardType><IsPrivate></IsPrivate><IsUrgent></IsUrgent><Amount>1.00</Amount><Currency>CNY</Currency><CertType>0</CertType><CertNum></CertNum><Mobile></Mobile><Purpose>省道测试是否的腹</Purpose><Memo>备注路口见到否</Memo><PolicyNumber></PolicyNumber><Extent1></Extent1><Extent2></Extent2><SourceTransNo>SO1726360000111307</SourceTransNo></Trans></RealTimeSingleTransReq></Root>";
        private static byte[] data = Encoding.GetEncoding("GBK").GetBytes(str);
        [Test]
        public void BigBytesData()
        {
            NetMQMessage plainMessage = new NetMQMessage();
            plainMessage.Append(new byte[255 * 255]);

            NetMQMessage cipherMessage = m_serverSecureChannel.EncryptApplicationMessage(plainMessage);
            var combineBytes =ToBytes(cipherMessage);
            bool serverChangeCipherSpec = m_serverSecureChannel.ChangeSuiteChangeArrived;
            int offset  =0;
            List<NetMQMessage> sslMessages;
            bool result = combineBytes.GetV0_2RecordLayerNetMQMessage(ref serverChangeCipherSpec,out offset,out sslMessages);

            Assert.AreEqual(result, true);
            var plainMessage1 = m_clientSecureChannel.DecryptApplicationMessage(sslMessages[0]);
            Assert.AreEqual(plainMessage.FrameCount, plainMessage1.FrameCount);
            Assert.AreEqual(plainMessage.Last.Buffer, plainMessage1.Last.Buffer);
        }
        [Test]
        public void MutiBytesData()
        {
            for (int i = 0; i < 100; i++)
            {
                NetMQMessage plainMessage = new NetMQMessage();
                plainMessage.Append(data);

                NetMQMessage cipherMessage = m_serverSecureChannel.EncryptApplicationMessage(plainMessage);
                var combineBytes =ToBytes(cipherMessage);
                bool serverChangeCipherSpec = m_serverSecureChannel.ChangeSuiteChangeArrived;
                int offset  =0;
                List<NetMQMessage> sslMessages;
                bool result = combineBytes.GetV0_2RecordLayerNetMQMessage(ref serverChangeCipherSpec,out offset,out sslMessages);

                Assert.AreEqual(result, true);
                var plainMessage1 = m_clientSecureChannel.DecryptApplicationMessage(sslMessages[0]);
                Assert.AreEqual(plainMessage.FrameCount, plainMessage1.FrameCount);
                Assert.AreEqual(plainMessage.Last.Buffer, plainMessage1.Last.Buffer);
            }
        }
        public static byte[] ToBytes(NetMQMessage message)
        {
            byte[] data = new byte[message.Sum(f => f.BufferSize)];
            int offset = 0;
            foreach (var frame in message)
            {
                Buffer.BlockCopy(frame.Buffer, 0, data, offset, frame.BufferSize);
                offset += frame.BufferSize;
            }
            return data;
        }
        [Test]
        public void MultipartMessage()
        {
            NetMQMessage plainMessage = new NetMQMessage();
            plainMessage.Append("Hello");
            plainMessage.Append("World");

            NetMQMessage cipherMessage = m_serverSecureChannel.EncryptApplicationMessage(plainMessage);


            byte[] combineBytes= new byte[0];
            int sum = 0;
            foreach (var frame in cipherMessage)
            {
                combineBytes = combineBytes.Combine(frame.Buffer);
                sum += frame.BufferSize;
            }
            List<NetMQMessage> sslMessages;
            Assert.AreEqual(sum, combineBytes.Length);
            int offset;
            bool serverChangeCipherSpec = m_serverSecureChannel.ChangeSuiteChangeArrived;
            bool result = combineBytes.GetV0_2RecordLayerNetMQMessage(ref serverChangeCipherSpec,out offset,out sslMessages);
            Assert.IsTrue(result);
            Assert.AreEqual(offset, combineBytes.Length);
            Assert.AreEqual(sslMessages.Count, 1);
            for (int j = 0; j < sslMessages[0].FrameCount; j++)
            {
                Assert.AreEqual(sslMessages[0][j].Buffer, cipherMessage[j].Buffer);
            }


            NetMQMessage decryptedMessage = m_clientSecureChannel.DecryptApplicationMessage(sslMessages[0]);
            Assert.AreEqual(decryptedMessage[0].ConvertToString(), plainMessage[0].ConvertToString());
            Assert.AreEqual(decryptedMessage[1].ConvertToString(), plainMessage[1].ConvertToString());
            Assert.AreEqual(decryptedMessage[0].ConvertToString(), "Hello");
            Assert.AreEqual(decryptedMessage[1].ConvertToString(), "World");
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
