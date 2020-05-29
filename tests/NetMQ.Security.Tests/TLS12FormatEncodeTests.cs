using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using NetMQ.Security;
using NetMQ.Security.Enums;
using NetMQ.Security.Extensions;
using NetMQ.Security.TLS12;
using NetMQ.Security.TLS12.HandshakeMessages;
using NetMQ.Security.TLS12.Layer;
using NUnit.Framework;

namespace NetMQ.Security.Tests
{
    [TestFixture]
    public class TLS12FormatEncodeTests
    {
        [Test]
        public void ClientHelloMessageTest()
        {
            ClientHelloMessage clientHelloMessage = new ClientHelloMessage();
            clientHelloMessage.Version = ProtocolVersion.TLS12;
            clientHelloMessage.Random = new byte[32];
            for(int i = 0; i < 32;i++)
            {
                clientHelloMessage.Random[i] = (byte)i;
            }
            clientHelloMessage.SessionID = new byte[0];

            clientHelloMessage.CipherSuites = new[]
            {
                CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
                CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA
            };

            string data = BitConverter.ToString(clientHelloMessage);
            Assert.AreEqual(data, "03-03-00-01-02-03-04-05-06-07-08-09-0A-0B-0C-0D-0E-0F-10-11-12-13-14-15-16-17-18-19-1A-1B-1C-1D-1E-1F-00-00-08-00-3D-00-35-00-3C-00-2F-01-00-00-00");

        }
        [Test]
        public void ServerHelloMessageTest()
        {
            ServerHelloMessage serverHelloMessage = new ServerHelloMessage();
            serverHelloMessage.Version = ProtocolVersion.TLS12;
            serverHelloMessage.Random = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                serverHelloMessage.Random[i] = (byte)i;
            }
            serverHelloMessage.SessionID = new byte[0];

            serverHelloMessage.CipherSuite = CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA;

            string data = BitConverter.ToString(serverHelloMessage);
            Assert.AreEqual(data, "03-03-00-01-02-03-04-05-06-07-08-09-0A-0B-0C-0D-0E-0F-10-11-12-13-14-15-16-17-18-19-1A-1B-1C-1D-1E-1F-00-00-2F-00");

        }
        [Test]
        public void CertificateMessageTest()
        {
            CertificateMessage serverHelloMessage = new CertificateMessage();
            serverHelloMessage.Certificate = new X509Certificate2(NUnit.Framework.TestContext.CurrentContext.TestDirectory + "\\server.pfx", "1234");
            string data = BitConverter.ToString(serverHelloMessage);
            Assert.AreEqual(data, BitConverter.ToString("00035d00035a308203563082023ea003020102020900e32c1aec6d99fd28300d06092a864886f70d01010b05003066310b3009060355040613026361310b300906035504080c026361310b3009060355040a0c026361310b3009060355040b0c026361310b300906035504030c0263613123302106092a864886f70d01090116146c696e676a4066696e676172642e636f6d2e636e301e170d3138303530313036343233325a170d3139303530313036343233325a3076310b3009060355040613027a68310b300906035504080c027a6a310b300906035504070c02687a310b3009060355040a0c026667310b3009060355040b0c026667310e300c06035504030c05446d5f63613123302106092a864886f70d01090116146c696e676a4066696e676172642e636f6d2e636e30819f300d06092a864886f70d010101050003818d0030818902818100cdd6bc2664dd1f3b835ddf69c72b28718f19e877b381a2e040d9e85f259434c0dd26e8cd22b2baf17ab2507f452e54a45e1fbc2f6ad0ef22fabd8e46829ffed48a6a373208fcccdc6714b4893d367d6d6fc2d698101091c81192762cc3c6ddbe96e0e90229c521a60e2972a096b8c1693d90d3e4a2ce8d35bff4cfd8b10a2c8b0203010001a37b307930090603551d1304023000302c06096086480186f842010d041f161d4f70656e53534c2047656e657261746564204365727469666963617465301d0603551d0e04160414ca14c9b21535c341863ac254b0ff79d3f77c4fc8301f0603551d2304183016801419dfa8bec9576e3f5eff9132b9a5358f36e46350300d06092a864886f70d01010b0500038201010034886beda4cb62a0cf69db7009bec9bbd475170f222d9af291774f9301e58598c342796c348c3dbc491261a778bce2294738caddece9bcfc608dcd89112ffad1615f4197dbf10d391cc28e2f349e2251f121f4298a494ddf9649b028c7244f081176fd298b598fe9421aa8b852fe147e04f7a2cd093feb6841184bf9bce19d17b4528409d437077b1ae2e3672e5c3db0c074fe71440dc33a18ffba67d5837a207fba2459aa9acc92af6bf303829b51811f262223ef97a6a6951a7a6852b4330ecca85370718b348aab525878750d11ba564ccbcc9b05783654f1ff971d79fde829ec309df91ef55c0b6f99679bff742fe3dc04e5b817d88a0b692f7cf232c10b".ConvertHexToByteArray2()));

        }
        [Test]
        public void ServerHelloDoneTest()
        {
            ServerHelloDoneMessage serverHelloDoneMessage = new ServerHelloDoneMessage();
            string data = BitConverter.ToString(serverHelloDoneMessage);
            Assert.AreEqual(data, "");
        }
        [Test]
        public void ClientKeyExchangeTest()
        {
            ClientKeyExchangeMessage clientKeyExchangeMessage = new ClientKeyExchangeMessage();
            clientKeyExchangeMessage.EncryptedPreMasterSecret = "5824d9ad49646385b44db6839f9452ad5b9abc3f77c8233b75822dbe032339c839a6df55b3765c8fc472567a27513dab7130056c3ed77bad10f47e25a2023b9d7ce2d292b2b8a40ea356b8bd7b7e580fafd171614e9e0c66d2b65f83d4bc1f903555546403a2ad6af27e24473789df4d2fae31bc64964090370b33983bb13811".ConvertHexToByteArray2();
            string data = BitConverter.ToString(clientKeyExchangeMessage);
            Assert.AreEqual(data, BitConverter.ToString("00805824d9ad49646385b44db6839f9452ad5b9abc3f77c8233b75822dbe032339c839a6df55b3765c8fc472567a27513dab7130056c3ed77bad10f47e25a2023b9d7ce2d292b2b8a40ea356b8bd7b7e580fafd171614e9e0c66d2b65f83d4bc1f903555546403a2ad6af27e24473789df4d2fae31bc64964090370b33983bb13811".ConvertHexToByteArray2()));
        }
        [Test]
        public void ChangeCipherSpecTest()
        {
            ChangeCipherSpecProtocol clientKeyExchangeMessage = new ChangeCipherSpecProtocol();
            string data = BitConverter.ToString(clientKeyExchangeMessage);
            Assert.AreEqual(data, "01");
        }
        [Test]
        public void FinishedMessageTest()
        {
            FinishedMessage message = new FinishedMessage();
            message.VerifyData = "589a9898ac8eb38a0c0d90823441449600eeb32ef8e11504b0752aad2654cf9d3eefb485a9b8c2aaf9d4e9f0ed46864287dd1ae06fa3861e34fe3ace59b729c2".ConvertHexToByteArray2();
            string data = BitConverter.ToString(message);
            Assert.AreEqual(data, BitConverter.ToString("589a9898ac8eb38a0c0d90823441449600eeb32ef8e11504b0752aad2654cf9d3eefb485a9b8c2aaf9d4e9f0ed46864287dd1ae06fa3861e34fe3ace59b729c2".ConvertHexToByteArray2()));
        }
        [Test]
        public void HandshakeProtocolClientHelloMessageTest()
        {
            HandshakeProtocol handshakeProtocol = new HandshakeProtocol();

            ClientHelloMessage clientHelloMessage = new ClientHelloMessage();
            clientHelloMessage.Version = ProtocolVersion.TLS12;
            clientHelloMessage.Random = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                clientHelloMessage.Random[i] = (byte)i;
            }
            clientHelloMessage.SessionID = new byte[0];

            clientHelloMessage.CipherSuites = new[]
            {
                CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
                CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA
            };

            handshakeProtocol.SetHandshakeMessage(clientHelloMessage);
            string data = BitConverter.ToString(handshakeProtocol);
            Assert.AreEqual(data, "01-00-00-31-03-03-00-01-02-03-04-05-06-07-08-09-0A-0B-0C-0D-0E-0F-10-11-12-13-14-15-16-17-18-19-1A-1B-1C-1D-1E-1F-00-00-08-00-3D-00-35-00-3C-00-2F-01-00-00-00");
        }
        [Test]
        public void HandshakeProtocolServerHelloMessageTest()
        {
            HandshakeProtocol handshakeProtocol = new HandshakeProtocol();

            ServerHelloMessage serverHelloMessage = new ServerHelloMessage();
            serverHelloMessage.Version = ProtocolVersion.TLS12;
            serverHelloMessage.Random = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                serverHelloMessage.Random[i] = (byte)i;
            }
            serverHelloMessage.SessionID = new byte[0];

            serverHelloMessage.CipherSuite = CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA;

            handshakeProtocol.SetHandshakeMessage(serverHelloMessage);
            string data = BitConverter.ToString(handshakeProtocol);
            Assert.AreEqual(data, "02-00-00-26-03-03-00-01-02-03-04-05-06-07-08-09-0A-0B-0C-0D-0E-0F-10-11-12-13-14-15-16-17-18-19-1A-1B-1C-1D-1E-1F-00-00-2F-00");
        }
        [Test]
        public void HandshakeProtocolCertificateMessageTest()
        {
            HandshakeProtocol handshakeProtocol = new HandshakeProtocol();

            CertificateMessage message = new CertificateMessage();
            message.Certificate = new X509Certificate2(NUnit.Framework.TestContext.CurrentContext.TestDirectory + "\\server.pfx", "1234");
            handshakeProtocol.SetHandshakeMessage(message);
            string data = BitConverter.ToString(handshakeProtocol);
            Assert.AreEqual(data, BitConverter.ToString("0b00036000035d00035a308203563082023ea003020102020900e32c1aec6d99fd28300d06092a864886f70d01010b05003066310b3009060355040613026361310b300906035504080c026361310b3009060355040a0c026361310b3009060355040b0c026361310b300906035504030c0263613123302106092a864886f70d01090116146c696e676a4066696e676172642e636f6d2e636e301e170d3138303530313036343233325a170d3139303530313036343233325a3076310b3009060355040613027a68310b300906035504080c027a6a310b300906035504070c02687a310b3009060355040a0c026667310b3009060355040b0c026667310e300c06035504030c05446d5f63613123302106092a864886f70d01090116146c696e676a4066696e676172642e636f6d2e636e30819f300d06092a864886f70d010101050003818d0030818902818100cdd6bc2664dd1f3b835ddf69c72b28718f19e877b381a2e040d9e85f259434c0dd26e8cd22b2baf17ab2507f452e54a45e1fbc2f6ad0ef22fabd8e46829ffed48a6a373208fcccdc6714b4893d367d6d6fc2d698101091c81192762cc3c6ddbe96e0e90229c521a60e2972a096b8c1693d90d3e4a2ce8d35bff4cfd8b10a2c8b0203010001a37b307930090603551d1304023000302c06096086480186f842010d041f161d4f70656e53534c2047656e657261746564204365727469666963617465301d0603551d0e04160414ca14c9b21535c341863ac254b0ff79d3f77c4fc8301f0603551d2304183016801419dfa8bec9576e3f5eff9132b9a5358f36e46350300d06092a864886f70d01010b0500038201010034886beda4cb62a0cf69db7009bec9bbd475170f222d9af291774f9301e58598c342796c348c3dbc491261a778bce2294738caddece9bcfc608dcd89112ffad1615f4197dbf10d391cc28e2f349e2251f121f4298a494ddf9649b028c7244f081176fd298b598fe9421aa8b852fe147e04f7a2cd093feb6841184bf9bce19d17b4528409d437077b1ae2e3672e5c3db0c074fe71440dc33a18ffba67d5837a207fba2459aa9acc92af6bf303829b51811f262223ef97a6a6951a7a6852b4330ecca85370718b348aab525878750d11ba564ccbcc9b05783654f1ff971d79fde829ec309df91ef55c0b6f99679bff742fe3dc04e5b817d88a0b692f7cf232c10b".ConvertHexToByteArray2()));
        }
        [Test]
        public void HandshakeProtocolServerHelloDoneMessageTest()
        {
            HandshakeProtocol handshakeProtocol = new HandshakeProtocol();

            ServerHelloDoneMessage message = new ServerHelloDoneMessage();

            handshakeProtocol.SetHandshakeMessage(message);
            string data = BitConverter.ToString(handshakeProtocol);
            Assert.AreEqual(data, BitConverter.ToString("0e000000".ConvertHexToByteArray2()));
        }
        [Test]
        public void HandshakeProtocolClientKeyExchangeMessageTest()
        {
            HandshakeProtocol handshakeProtocol = new HandshakeProtocol();
            ClientKeyExchangeMessage message = new ClientKeyExchangeMessage();
            message.EncryptedPreMasterSecret = "5824d9ad49646385b44db6839f9452ad5b9abc3f77c8233b75822dbe032339c839a6df55b3765c8fc472567a27513dab7130056c3ed77bad10f47e25a2023b9d7ce2d292b2b8a40ea356b8bd7b7e580fafd171614e9e0c66d2b65f83d4bc1f903555546403a2ad6af27e24473789df4d2fae31bc64964090370b33983bb13811".ConvertHexToByteArray2();
            handshakeProtocol.SetHandshakeMessage(message);
            string data = BitConverter.ToString(handshakeProtocol);
            Assert.AreEqual(data, BitConverter.ToString("1000008200805824d9ad49646385b44db6839f9452ad5b9abc3f77c8233b75822dbe032339c839a6df55b3765c8fc472567a27513dab7130056c3ed77bad10f47e25a2023b9d7ce2d292b2b8a40ea356b8bd7b7e580fafd171614e9e0c66d2b65f83d4bc1f903555546403a2ad6af27e24473789df4d2fae31bc64964090370b33983bb13811".ConvertHexToByteArray2()));
        }
    }
}
