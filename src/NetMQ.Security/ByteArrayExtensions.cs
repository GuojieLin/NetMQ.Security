using NetMQ.Security.V0_1;
using NetMQ.Security.V0_1.HandshakeMessages;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NetMQ.Security
{
    public static class ByteArrayExtensions
    {

        public static byte[] Combine(this byte[] bytes1, byte[] bytes2)
        {
            byte[] c = new byte[bytes1.Length + bytes2.Length];

            Buffer.BlockCopy(bytes1, 0, c, 0, bytes1.Length);
            Buffer.BlockCopy(bytes2, 0, c, bytes1.Length, bytes2.Length);
            return c;
        }
        public static bool GetV0_2RecordLayerNetMQMessage(this byte[] bytes, ref bool changeCipherSpec, out int offset, out List<NetMQMessage> sslMessages)
        {
            sslMessages = new List<NetMQMessage>();
            offset = 0;
            do
            {
                NetMQMessage  sslMessage;
                if (GetV0_2RecordLayerNetMQMessage(bytes, ref changeCipherSpec, ref offset, out sslMessage))
                {
                    sslMessages.Add(sslMessage);
                }
                else
                {
                    break;
                }
            } while (offset < bytes.Length);
            return sslMessages.Count > 0;
        }
        /// <summary>
        /// 将字节数组解析出ssl record layer格式。V3_3
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public static bool GetV0_2RecordLayerNetMQMessage(this byte[] bytes, ref bool changeCipherSpec, ref int offset, out NetMQMessage sslMessage)
        {
            if (bytes.Length - offset < 5)
            {
                //长度至少要有5位
                //ContentType (1,handshake:22)
                //ProtocolVersion(2)
                //握手协议长度：(2)
                //握手协议数据
                sslMessage = null;
                return false;
            }
            sslMessage = new NetMQMessage();
            byte[] contentTypeBytes = new byte[Constants.CONTENT_TYPE_LENGTH];
            //get content type
            Buffer.BlockCopy(bytes, offset, contentTypeBytes, 0, Constants.CONTENT_TYPE_LENGTH);
            offset += Constants.CONTENT_TYPE_LENGTH;
            byte[] protocolVersionBytes = new byte[Constants.PROTOCOL_VERSION_LENGTH];
            //get protocol version
            Buffer.BlockCopy(bytes, offset, protocolVersionBytes, 0, Constants.PROTOCOL_VERSION_LENGTH);
            offset += Constants.PROTOCOL_VERSION_LENGTH;
            byte[] handshakeLengthBytes = new byte[Constants.HAND_SHAKE_LENGTH];
            //get hand shake layer
            //0012->1200->2100
            Buffer.BlockCopy(bytes, offset, handshakeLengthBytes, 0, Constants.HAND_SHAKE_LENGTH);
            offset += Constants.HAND_SHAKE_LENGTH;
            //交换2个字节位置。
            byte[] temp = new byte[4];
            temp[1] = handshakeLengthBytes[0];
            temp[0] = handshakeLengthBytes[1];
            //由于生成长度是BitConverter.GetBytes是Little-Endian,因此需要转换为Big-Endian。
            //在解析长度时需要转回来。
            //一定要4位才行
            int length = BitConverter.ToInt32(temp, 0);
            //解析handshake长度
            if (offset + length > bytes.Length)
            {
                sslMessage = null;
                //接收到的数据长度不够，可能发送拆包。等后续包过来。
                return false;
            }
            sslMessage.Append(contentTypeBytes);
            sslMessage.Append(protocolVersionBytes);
            sslMessage.Append(handshakeLengthBytes);
            byte[] handShakeLayerBytes = new byte[length];
            Buffer.BlockCopy(bytes, offset, handShakeLayerBytes, 0, length);
            offset += length;
            //解析handShakeLayer
            GetNextLayer(contentTypeBytes, handShakeLayerBytes, sslMessage, ref changeCipherSpec);
            return true;
        }

        #region private method
        private static void GetNextLayer(byte[] contentTypeBytes, byte[] handShakeLayerBytes, NetMQMessage sslMessage, ref bool changeCipherSpec)
        {
            ContentType contentType = (ContentType)contentTypeBytes[0];
            switch (contentType)
            {
                case ContentType.Handshake:
                    GetHandShakeLayer(handShakeLayerBytes, sslMessage, changeCipherSpec);
                    break;
                case ContentType.ChangeCipherSpec:
                    GetChangeCipherSpecLayer(handShakeLayerBytes, sslMessage);
                    //后续都加密
                    changeCipherSpec = true;
                    break;
                case ContentType.ApplicationData:
                    GetApplicationDataLayer(handShakeLayerBytes, sslMessage);
                    break;
            }
        }


        private static void GetChangeCipherSpecLayer(byte[] bytes, NetMQMessage sslMessage)
        {
            sslMessage.Append(bytes);
        }
        private static void GetApplicationDataLayer(byte[] bytes, NetMQMessage sslMessage)
        {
            //iv长度
            int offset = 0;
            byte[] ivLengthBytes= new byte[Constants.IV_LENGTH];
            //get hand shake content length
            Buffer.BlockCopy(bytes, offset, ivLengthBytes, 0, Constants.IV_LENGTH);
            int length = GetLength(ivLengthBytes);
            sslMessage.Append(ivLengthBytes);
            offset += Constants.IV_LENGTH;


            byte[] ivBytes = new byte[length];
            Buffer.BlockCopy(bytes, offset, ivBytes, 0, length);
            offset += length;
            sslMessage.Append(ivBytes);

            while (offset < bytes.Length)
            {
                byte[] contentLengthBytes= new byte[Constants.CONTENT_LENGTH];
                //get hand shake content length
                Buffer.BlockCopy(bytes, offset, contentLengthBytes, 0, Constants.CONTENT_LENGTH);
                length = GetLength(contentLengthBytes);
                sslMessage.Append(contentLengthBytes);
                offset += Constants.CONTENT_LENGTH;
                byte[] contentBytes= new byte[length];
                //get hand shake content length
                Buffer.BlockCopy(bytes, offset, contentBytes, 0, length);
                sslMessage.Append(contentBytes);
                offset += length;
            }
        }


        private static void GetHandShakeLayer(byte[] bytes, NetMQMessage sslMessage, bool changeCipherSpec)
        {
            if (changeCipherSpec)
            {
                //加密的数据
                GetApplicationDataLayer(bytes, sslMessage);
            }
            else
            {
                HandshakeType handshakeType = GetHandshakeType(bytes,sslMessage);
                switch (handshakeType)
                {
                    case HandshakeType.ClientHello:
                        GetClientHelloLayer(handshakeType, bytes, sslMessage);
                        break;
                    case HandshakeType.ServerHello:
                        GetServerHelloLayer(handshakeType, bytes, sslMessage);
                        break;
                    case HandshakeType.Certificate:
                        GetCertificateLayer(handshakeType, bytes, sslMessage);
                        break;
                    case HandshakeType.ServerHelloDone:
                        GetServerHelloDoneLayer(handshakeType, bytes, sslMessage);
                        break;
                    case HandshakeType.ClientKeyExchange:
                        GetClientKeyExchangeLayer(handshakeType, bytes, sslMessage);
                        break;
                    case HandshakeType.Finished:
                        GetFinishLayer(handshakeType, bytes, sslMessage);
                        break;
                }
            }
        }

        private static int GetLength(byte[] lengthBytes)
        {
            byte[] tempLength = new byte[2];
            tempLength[0] = lengthBytes[1];
            tempLength[1] = lengthBytes[0];
            int length = BitConverter.ToInt16(tempLength, 0);
            return length;
        }

        private static HandshakeType GetHandshakeType(byte[] bytes, NetMQMessage sslMessage)
        {
            byte[] handShakeBytes = new byte[Constants.HAND_SHAKE_TYPE];
            //get content type
            Buffer.BlockCopy(bytes, 0, handShakeBytes, 0, Constants.HAND_SHAKE_TYPE);
            HandshakeType handshakeType = (HandshakeType) handShakeBytes[0];
            sslMessage.Append(handShakeBytes);
            return handshakeType;
        }
        private static void GetHandShakeContentLength(byte[] bytes, ref int offset, NetMQMessage sslMessage)
        {
            byte[] handShakeContentLengthBytes= new byte[Constants.HAND_SHAKE_CONTENT_LENGTH];
            //get hand shake content length
            Buffer.BlockCopy(bytes, offset, handShakeContentLengthBytes, 0, Constants.HAND_SHAKE_CONTENT_LENGTH);
            sslMessage.Append(handShakeContentLengthBytes);
            offset += Constants.HAND_SHAKE_CONTENT_LENGTH;
        }
        private static void GetProtocolVersion(byte[] bytes, ref int offset, NetMQMessage sslMessage)
        {
            byte[] protocolVersionBytes = new byte[Constants.PROTOCOL_VERSION_LENGTH];
            //get protocol version
            Buffer.BlockCopy(bytes, offset, protocolVersionBytes, 0, Constants.PROTOCOL_VERSION_LENGTH);
            sslMessage.Append(protocolVersionBytes);
            offset += Constants.PROTOCOL_VERSION_LENGTH;
        }
        private static void GetRandom(byte[] bytes, ref int offset, NetMQMessage sslMessage)
        {
            byte[] randomBytes = new byte[Constants.RANDOM_LENGTH];
            //get random version
            Buffer.BlockCopy(bytes, offset, randomBytes, 0, Constants.RANDOM_LENGTH);
            sslMessage.Append(randomBytes);
            offset += Constants.RANDOM_LENGTH;
        }
        /// <summary>
        /// 解析ClientHello格式
        /// </summary>
        /// <param name="handshakeType"></param>
        /// <param name="bytes"></param>
        /// <param name="sslMessage"></param>
        private static void GetClientHelloLayer(HandshakeType handshakeType, byte[] bytes, NetMQMessage sslMessage)
        {
            int offset = 1;
            GetHandShakeContentLength(bytes, ref offset, sslMessage);
            GetProtocolVersion(bytes, ref offset, sslMessage);
            GetRandom(bytes, ref offset, sslMessage);

            byte[] cipherSuiteslengthBytes = new byte[Constants.CIPHER_SUITES_LENGTH];
            //get Cipher Suites Length version
            Buffer.BlockCopy(bytes, offset, cipherSuiteslengthBytes, 0, Constants.CIPHER_SUITES_LENGTH);
            sslMessage.Append(cipherSuiteslengthBytes);
            offset += Constants.CIPHER_SUITES_LENGTH;

            byte[] cipherSuitesBytes = new byte[bytes.Length - offset];
            //get Cipher Suites version
            Buffer.BlockCopy(bytes, offset, cipherSuitesBytes, 0, bytes.Length - offset);
            sslMessage.Append(cipherSuitesBytes);
        }
        /// <summary>
        /// 解析ServerHello格式
        /// </summary>
        /// <param name="handshakeType"></param>
        /// <param name="bytes"></param>
        /// <param name="sslMessage"></param>
        private static void GetServerHelloLayer(HandshakeType handshakeType, byte[] bytes, NetMQMessage sslMessage)
        {
            int offset = 1;

            GetHandShakeContentLength(bytes, ref offset, sslMessage);

            GetProtocolVersion(bytes, ref offset, sslMessage);

            GetRandom(bytes, ref offset, sslMessage);

            byte[] cipherSuiteBytes = new byte[Constants.CIPHER_SUITE_LENGTH];
            //get Cipher Suites Length version
            Buffer.BlockCopy(bytes, offset, cipherSuiteBytes, 0, Constants.CIPHER_SUITE_LENGTH);
            sslMessage.Append(cipherSuiteBytes);
        }

        /// <summary>
        /// 解析Certificate格式
        /// </summary>
        /// <param name="handshakeType"></param>
        /// <param name="bytes"></param>
        /// <param name="sslMessage"></param>
        private static void GetCertificateLayer(HandshakeType handshakeType, byte[] bytes, NetMQMessage sslMessage)
        {
            int offset = 1;
            GetHandShakeContentLength(bytes, ref offset, sslMessage);

            byte[] certificateBytes = new byte[bytes.Length - offset];
            //get Cipher Suites Length version
            Buffer.BlockCopy(bytes, offset, certificateBytes, 0, bytes.Length - offset);
            sslMessage.Append(certificateBytes);
        }
        private static void GetServerHelloDoneLayer(HandshakeType handshakeType, byte[] bytes, NetMQMessage sslMessage)
        {
            int offset = 1;
            byte[] handShakeContentLengthBytes= new byte[Constants.HAND_SHAKE_CONTENT_LENGTH];
            //get hand shake content length
            Buffer.BlockCopy(bytes, offset, handShakeContentLengthBytes, 0, Constants.HAND_SHAKE_CONTENT_LENGTH);
            sslMessage.Append(handShakeContentLengthBytes);
        }
        /// <summary>
        /// ContentType (1,handshake:22)
        /// ProtocolVersion(2:0303)
        /// 握手协议长度：(2)
        /// 握手协议数据
        ///     HandShakeType(ClientKeyExchange:16)
        ///     长度(3)
        ///     内容
        ///         密钥长度
        ///         密钥
        /// </summary>
        /// <param name="handshakeType"></param>
        /// <param name="bytes"></param>
        /// <param name="sslMessage"></param>
        private static void GetClientKeyExchangeLayer(HandshakeType handshakeType, byte[] bytes, NetMQMessage sslMessage)
        {
            int offset = 1;
            GetHandShakeContentLength(bytes, ref offset, sslMessage);

            byte[] clientKeyExchangeBytes = new byte[bytes.Length - offset];
            //get master key 
            Buffer.BlockCopy(bytes, offset, clientKeyExchangeBytes, 0, bytes.Length - offset);
            sslMessage.Append(clientKeyExchangeBytes);
        }
        /// <summary>
        /// ContentType (1,handshake:22)
        /// ProtocolVersion(2:0303)
        /// 握手协议长度：(2)
        /// 握手协议数据
        ///     HandShakeType(finished:20)
        ///     VerifyData
        /// </summary>
        /// <param name="handshakeType"></param>
        /// <param name="bytes"></param>
        /// <param name="sslMessage"></param>
        private static void GetFinishLayer(HandshakeType handshakeType, byte[] bytes, NetMQMessage sslMessage)
        {
            int offset = 1;
            byte[] verifyDataBytes = new byte[bytes.Length - offset];
            //get master key length
            Buffer.BlockCopy(bytes, offset, verifyDataBytes, 0, bytes.Length - offset);
            sslMessage.Append(verifyDataBytes);
        }
        #endregion
    }
}
