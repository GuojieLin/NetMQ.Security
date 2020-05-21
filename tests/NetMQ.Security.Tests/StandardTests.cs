using NetMQ.Security.V0_1;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace NetMQ.Security.Tests
{
    [TestFixture]
    public class StandardTests
    {

        [Test]
        [Ignore("不用了")]
        public void StandardTest()
        {
            Configuration configuration = new Configuration() { VerifyCertificate = false, StandardTLSFormat = true };
            X509Certificate2 certificate = new X509Certificate2(NUnit.Framework.TestContext.CurrentContext.TestDirectory + "\\server.pfx", "1234");

            SecureChannel serverSecureChannel = SecureChannel.CreateServerSecureChannel(configuration);
            serverSecureChannel.Certificate = certificate;

            SecureChannel clientSecureChannel = SecureChannel.CreateClientSecureChannel(null, configuration);
            IList<NetMQMessage> clientOutgoingMessages = new List<NetMQMessage>();
            IList<NetMQMessage> serverOutgoingMessages = new List<NetMQMessage>();
            bool serverComplete = false;

            bool clientComplete = clientSecureChannel.ProcessMessage(null, clientOutgoingMessages);
            Assert.AreEqual(clientOutgoingMessages.Count, 1);
            string clientHelloHex = BitConverter.ToString(clientOutgoingMessages[0].Last.Buffer, 0).Replace("-", string.Empty).ToLower();
            Assert.AreEqual(clientHelloHex, "16030300820100007e03035ec254f6faccf140beec3b43441c72c325ed437a5dcfa21733269448f7cb34f9000012c02cc02bc02fc030c013c014009c002f003501000043000a001600140017001800190009000a000b000c000d000e0016000b00020100000d00160014060306010503050104030401040202030201020200170000ff01000100");
            //第一次握手处理 client hello
            List<NetMQMessage> sslMessages;
            int offset;
            bool result = serverSecureChannel.ResolveRecordLayer(clientOutgoingMessages[0].First.Buffer, out offset, out sslMessages);
            Assert.IsTrue(result);
            Assert.AreEqual(sslMessages.Count, 1);

            Assert.AreEqual(offset, clientOutgoingMessages[0].First.BufferSize);
            serverComplete = serverSecureChannel.ProcessMessage(sslMessages[0], serverOutgoingMessages);
            Assert.IsFalse(serverComplete);
            clientOutgoingMessages.Clear();


            //server hello , certificate,serverHelloDon
            Assert.AreEqual(serverOutgoingMessages.Count, 3);

            string serverHelloHex = BitConverter.ToString(serverOutgoingMessages[0].Last.Buffer, 0).Replace("-", string.Empty).ToLower();
            Assert.AreEqual(serverHelloHex, "160303004a020000460303aef1ba123a543c517b3d498705806e6745c57677742601d9b9da6979e2841d37203761363635643738366261363432626438366162326163393631353437343361002f00");
            string certificateHex = BitConverter.ToString(serverOutgoingMessages[1].Last.Buffer, 0).Replace("-", string.Empty).ToLower();
            Assert.AreEqual(certificateHex, "16030303640b00036000035d00035a308203563082023ea003020102020900e32c1aec6d99fd28300d06092a864886f70d01010b05003066310b3009060355040613026361310b300906035504080c026361310b3009060355040a0c026361310b3009060355040b0c026361310b300906035504030c0263613123302106092a864886f70d01090116146c696e676a4066696e676172642e636f6d2e636e301e170d3138303530313036343233325a170d3139303530313036343233325a3076310b3009060355040613027a68310b300906035504080c027a6a310b300906035504070c02687a310b3009060355040a0c026667310b3009060355040b0c026667310e300c06035504030c05446d5f63613123302106092a864886f70d01090116146c696e676a4066696e676172642e636f6d2e636e30819f300d06092a864886f70d010101050003818d0030818902818100cdd6bc2664dd1f3b835ddf69c72b28718f19e877b381a2e040d9e85f259434c0dd26e8cd22b2baf17ab2507f452e54a45e1fbc2f6ad0ef22fabd8e46829ffed48a6a373208fcccdc6714b4893d367d6d6fc2d698101091c81192762cc3c6ddbe96e0e90229c521a60e2972a096b8c1693d90d3e4a2ce8d35bff4cfd8b10a2c8b0203010001a37b307930090603551d1304023000302c06096086480186f842010d041f161d4f70656e53534c2047656e657261746564204365727469666963617465301d0603551d0e04160414ca14c9b21535c341863ac254b0ff79d3f77c4fc8301f0603551d2304183016801419dfa8bec9576e3f5eff9132b9a5358f36e46350300d06092a864886f70d01010b0500038201010034886beda4cb62a0cf69db7009bec9bbd475170f222d9af291774f9301e58598c342796c348c3dbc491261a778bce2294738caddece9bcfc608dcd89112ffad1615f4197dbf10d391cc28e2f349e2251f121f4298a494ddf9649b028c7244f081176fd298b598fe9421aa8b852fe147e04f7a2cd093feb6841184bf9bce19d17b4528409d437077b1ae2e3672e5c3db0c074fe71440dc33a18ffba67d5837a207fba2459aa9acc92af6bf303829b51811f262223ef97a6a6951a7a6852b4330ecca85370718b348aab525878750d11ba564ccbcc9b05783654f1ff971d79fde829ec309df91ef55c0b6f99679bff742fe3dc04e5b817d88a0b692f7cf232c10b");
            string serverHelloDonHex = BitConverter.ToString(serverOutgoingMessages[2].Last.Buffer, 0).Replace("-", string.Empty).ToLower();
            Assert.AreEqual(serverHelloDonHex, "16030300040e000000");

            //server hello
            result = clientSecureChannel.ResolveRecordLayer(serverOutgoingMessages[0].First.Buffer, out offset, out sslMessages);
            Assert.IsTrue(result);
            Assert.AreEqual(sslMessages.Count, 1);
            serverComplete = clientSecureChannel.ProcessMessage(sslMessages[0], clientOutgoingMessages);
            Assert.IsFalse(serverComplete);
            Assert.AreEqual(clientOutgoingMessages.Count, 0);


            result = clientSecureChannel.ResolveRecordLayer(serverOutgoingMessages[1].First.Buffer, out offset, out sslMessages);
            Assert.IsTrue(result);
            Assert.AreEqual(sslMessages.Count, 1);
            serverComplete = clientSecureChannel.ProcessMessage(sslMessages[0], clientOutgoingMessages);
            Assert.IsFalse(serverComplete);
            Assert.AreEqual(clientOutgoingMessages.Count, 0);

            result = clientSecureChannel.ResolveRecordLayer(serverOutgoingMessages[2].First.Buffer, out offset, out sslMessages);
            Assert.IsTrue(result);
            Assert.AreEqual(sslMessages.Count, 1);
            serverComplete = clientSecureChannel.ProcessMessage(sslMessages[0], clientOutgoingMessages);
            Assert.IsFalse(serverComplete);
            Assert.AreEqual(clientOutgoingMessages.Count, 3);
            serverOutgoingMessages.Clear();

            //Client Key Exchange, Change Cipher Spec, Encrypted Handshake Message
            string clientKeyExchangeHex = BitConverter.ToString(clientOutgoingMessages[0].Last.Buffer, 0).Replace("-", string.Empty).ToLower();
            //Assert.AreEqual(clientKeyExchangeHex, "16030300861000008200808235f62f3440e787404386cbbe865031cee225b50317950753280c6d9f433e396efacd0d92dd32052b5e9ea9e5b373d79c2bfaa81bcdeef842c4f549558a6248163b9a3c4cc7a8aea57fe479ed0577221a391f268c06bc3f0371d4d9fcbc135ee5060c0dd90f621e5519757e30f54cc21dc3a852ca2696522d3337b512117a6f");

            string changeCipherSpecHex = BitConverter.ToString(clientOutgoingMessages[1].Last.Buffer, 0).Replace("-", string.Empty).ToLower();
            Assert.AreEqual(changeCipherSpecHex, "140303000101");
            string encryptedHandshakeMessage = BitConverter.ToString(clientOutgoingMessages[2].Last.Buffer, 0).Replace("-", string.Empty).ToLower();
            //Assert.AreEqual(encryptedHandshakeMessage, "1603030040b5aae84a8ca06fcfc4a7a1974daf6cacc822e7286beb9ef161a5020b7cf2b2e2a024dc514059114016b05100c03ddd73bbca01bb72a939773bba2c9cd4497c89");

            result = serverSecureChannel.ResolveRecordLayer(clientOutgoingMessages[0].First.Buffer, out offset, out sslMessages);
            Assert.IsTrue(result);
            Assert.AreEqual(sslMessages.Count, 1);
            serverComplete = serverSecureChannel.ProcessMessage(sslMessages[0], serverOutgoingMessages);
            Assert.IsFalse(serverComplete);
            Assert.AreEqual(serverOutgoingMessages.Count, 1);
            changeCipherSpecHex = BitConverter.ToString(serverOutgoingMessages[0].Last.Buffer, 0).Replace("-", string.Empty).ToLower();
            Assert.AreEqual(changeCipherSpecHex, "140303000101");

            result = serverSecureChannel.ResolveRecordLayer(clientOutgoingMessages[1].First.Buffer, out offset, out sslMessages);
            Assert.IsTrue(result);
            Assert.AreEqual(sslMessages.Count, 1);
            serverComplete = serverSecureChannel.ProcessMessage(sslMessages[0], serverOutgoingMessages);
            Assert.IsFalse(serverComplete);
            Assert.IsTrue(serverSecureChannel.ChangeSuiteChangeArrived);
            Assert.AreEqual(serverOutgoingMessages.Count, 0);
            result = serverSecureChannel.ResolveRecordLayer(clientOutgoingMessages[2].First.Buffer, out offset, out sslMessages);
            Assert.IsTrue(result);
            Assert.AreEqual(sslMessages.Count, 1);
            serverComplete = serverSecureChannel.ProcessMessage(sslMessages[0], serverOutgoingMessages);
            Assert.IsFalse(serverComplete);
            Assert.AreEqual(serverOutgoingMessages.Count, 1);
            clientOutgoingMessages.Clear();

            clientSecureChannel.Dispose();
            serverSecureChannel.Dispose();
        }
    }
}
