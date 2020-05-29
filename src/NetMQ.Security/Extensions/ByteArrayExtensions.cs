using NetMQ.Security.Enums;
using NetMQ.Security.TLS12;
using NetMQ.Security.TLS12.HandshakeMessages;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace NetMQ.Security.Extensions
{
    public static class ByteArrayExtensions
    {
        public static byte[] LengthToBigEndianBytes(this byte[] bytes, int length)
        {
            if (length > 4) throw new ArgumentException("max length 4 byte");
            byte[] temp = BitConverter.GetBytes(bytes.Length);
            //由于BitConverter.GetBytes是Little-Endian,因此需要转换为Big-Endian
            return temp.Take(length).Reverse().ToArray();
        }
        public static byte[] LengthToLittleEndianBytes(this byte[] bytes, int length)
        {
            if (length > 4) throw new ArgumentException("max length 4 byte");
            byte[] temp = BitConverter.GetBytes(bytes.Length);
            //由于BitConverter.GetBytes是Little-Endian,因此需要转换为Big-Endian
            return temp.Take(length).ToArray();
        }

        public static byte[] Combine(this byte[] bytes1, byte[] bytes2)
        {
            byte[] c = new byte[bytes1.Length + bytes2.Length];

            Buffer.BlockCopy(bytes1, 0, c, 0, bytes1.Length);
            Buffer.BlockCopy(bytes2, 0, c, bytes1.Length, bytes2.Length);
            return c;
        }
        /// <summary>
        /// 将字节数组解析出ssl record layer格式。V3_3
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        [Obsolete("不再使用NetMQMessage解析TLS协议RecordLayer层")]
        public static bool GetRecordLayerNetMQMessage(this byte[] bytes, ref bool changeCipherSpec, ref int offset, out List<NetMQMessage> sslMessages)
        {
            //用一个临时遍历保存偏移量，只有这个当前解析成功才偏移。
            int tempOffset = offset;
            if (bytes.Length - tempOffset < 5)
            {
                //长度至少要有5位
                //ContentType (1,handshake:22)
                //ProtocolVersion(2)
                //握手协议长度：(2)
                //握手协议数据
                sslMessages = null;
                return false;
            }
            NetMQMessage sslMessage = new NetMQMessage();
            byte[] contentTypeBytes = new byte[Constants.CONTENT_TYPE_LENGTH];
            //get content type
            Buffer.BlockCopy(bytes, tempOffset, contentTypeBytes, 0, Constants.CONTENT_TYPE_LENGTH);
            tempOffset += Constants.CONTENT_TYPE_LENGTH;
            byte[] protocolVersionBytes = new byte[Constants.PROTOCOL_VERSION_LENGTH];
            //get protocol version
            Buffer.BlockCopy(bytes, tempOffset, protocolVersionBytes, 0, Constants.PROTOCOL_VERSION_LENGTH);
            tempOffset += Constants.PROTOCOL_VERSION_LENGTH;
            byte[] handshakeLengthBytes = new byte[Constants.RECORD_LAYER_LENGTH];
            //get hand shake layer
            //0012->1200->2100
            Buffer.BlockCopy(bytes, tempOffset, handshakeLengthBytes, 0, Constants.RECORD_LAYER_LENGTH);
            tempOffset += Constants.RECORD_LAYER_LENGTH;
            //交换2个字节位置。
            byte[] temp = new byte[2];
            temp[1] = handshakeLengthBytes[0];
            temp[0] = handshakeLengthBytes[1];
            //由于生成长度是BitConverter.GetBytes是Little-Endian,因此需要转换为Big-Endian。
            //在解析长度时需要转回来。
            //一定要4位才行
            int length = BitConverter.ToUInt16(temp, 0);
            //解析handshake长度
            if (tempOffset + length > bytes.Length)
            {
                sslMessages = null;
                //接收到的数据长度不够，可能发送拆包。等后续包过来。
                return false;
            }

            sslMessage.Append(contentTypeBytes);
            sslMessage.Append(protocolVersionBytes);
            sslMessage.Append(handshakeLengthBytes);
            //解析handShakeLayer或applicationdata
            sslMessages = GetRecordLayers((ContentType)contentTypeBytes[0], bytes, tempOffset, tempOffset + length, ref changeCipherSpec);
            tempOffset += length;
            offset = tempOffset;
            foreach (NetMQMessage record in sslMessages)
            {
                //每个record都添加头部
                foreach (NetMQFrame head in sslMessage.Reverse())//倒置，先插入后面的。
                {
                    record.Push(head.Buffer);
                }
            }
            return true;
        }

        #region private method
        [Obsolete("不再使用NetMQMessage解析TLS协议RecordLayer层")]
        private static List<NetMQMessage> GetRecordLayers(ContentType contentType, byte[] handShakeLayerBytes, int start,int end, ref bool changeCipherSpec)
        {
            List<NetMQMessage> sslMessages = new List<NetMQMessage>();
            int offset = start;
            do
            {

                NetMQMessage record = null;
                switch (contentType)
                {
                    case ContentType.Handshake:
                        record = GetHandShakeLayer(handShakeLayerBytes, ref offset, end, changeCipherSpec);
                        break;
                    case ContentType.ChangeCipherSpec:
                        record = GetChangeCipherSpecLayer(handShakeLayerBytes, ref offset);
                        //后续都加密
                        changeCipherSpec = true;
                        break;
                    case ContentType.ApplicationData:
                        record = GetApplicationDataLayer(handShakeLayerBytes, end, ref offset);
                        break;
                    case ContentType.Alert:
                        //可能加密，加载全部
                        record = GetAlertLayer(handShakeLayerBytes, ref offset);
                        break;
                }
                sslMessages.Add(record);
            } while (offset < end);
            return sslMessages;
        }


        [Obsolete("不再使用NetMQMessage解析TLS协议RecordLayer层")]
        private static NetMQMessage GetChangeCipherSpecLayer(byte[] bytes, ref int offset)
        {
            NetMQMessage sslMessage = new NetMQMessage();
            sslMessage.Append(bytes[offset++]);
            return sslMessage;
        }
        [Obsolete("不再使用NetMQMessage解析TLS协议RecordLayer层")]
        private static NetMQMessage GetAlertLayer(byte[] bytes, ref int offset)
        {
            NetMQMessage sslMessage = new NetMQMessage();
            sslMessage.Append(new byte[] { bytes[offset] });
            sslMessage.Append(new byte[] { bytes[offset+1] });
            offset += 2;
            return sslMessage;
        }
        [Obsolete("不再使用NetMQMessage解析TLS协议RecordLayer层")]
        private static NetMQMessage GetApplicationDataLayer(byte[] bytes, int end, ref int offset)
        {
            if (end > bytes.Length) end = bytes.Length;
            int length = end - offset;
            byte[] data = new byte[length];
            Buffer.BlockCopy(bytes, offset, data, 0, data.Length);
            NetMQMessage sslMessage = new NetMQMessage();
            sslMessage.Append(data);
            offset += data.Length;
            return sslMessage;
        }


        [Obsolete("不再使用NetMQMessage解析TLS协议RecordLayer层")]
        private static NetMQMessage GetHandShakeLayer(byte[] bytes, ref int offset ,int end, bool changeCipherSpec)
        {
            NetMQMessage sslMessage = new NetMQMessage();
            if (changeCipherSpec)
            {
                //握手时若密钥套件已就绪，需要全部读取。数据需要解密。
                //该消息一定是Finished
                sslMessage = GetApplicationDataLayer(bytes, end, ref offset);
            }
            else
            {
                //一个record内会有多提奥握手数据
                HandshakeType handshakeType = GetHandshakeType(bytes, ref offset, sslMessage);
                switch (handshakeType)
                {
                    case HandshakeType.HelloRequest:
                        break;
                    case HandshakeType.ClientHello:
                         GetClientHelloLayer(handshakeType, bytes, ref offset, sslMessage);
                        break;
                    case HandshakeType.ServerHello:
                         GetServerHelloLayer(handshakeType, bytes, ref offset, sslMessage);
                        break;
                    case HandshakeType.Certificate:
                         GetCertificateLayer(handshakeType, bytes, ref offset, sslMessage);
                        break;
                    case HandshakeType.ServerHelloDone:
                         GetServerHelloDoneLayer(handshakeType, bytes, ref offset, sslMessage);
                        break;
                    case HandshakeType.ClientKeyExchange:
                         GetClientKeyExchangeLayer(handshakeType, bytes, ref offset, sslMessage);
                        break;
                    case HandshakeType.Finished:
                         GetFinishLayer(handshakeType, bytes, ref offset, sslMessage);
                        break;
                }
            }
            Debug.Assert(offset <= bytes.Length);
            return sslMessage;
        }

        [Obsolete("不再使用NetMQMessage解析TLS协议RecordLayer层")]
        private static HandshakeType GetHandshakeType(byte[] bytes, ref int offset, NetMQMessage sslMessage)
        {
            HandshakeType handshakeType = (HandshakeType)bytes[offset];
            sslMessage.Append(new[] { (byte)handshakeType });
            offset += Constants.HAND_SHAKE_TYPE;
            return handshakeType;
        }
        [Obsolete("不再使用NetMQMessage解析TLS协议RecordLayer层")]
        private static int GetHandShakeContentLength(byte[] bytes, ref int offset, NetMQMessage sslMessage)
        {
            byte[] handShakeContentLengthBytes= new byte[Constants.HAND_SHAKE_LENGTH];
            //get hand shake content length
            Buffer.BlockCopy(bytes, offset, handShakeContentLengthBytes, 0, Constants.HAND_SHAKE_LENGTH);
            sslMessage.Append(handShakeContentLengthBytes);
            offset += Constants.HAND_SHAKE_LENGTH;
            int length = BitConverter.ToInt32(new[] { handShakeContentLengthBytes[2], handShakeContentLengthBytes[1], handShakeContentLengthBytes[0], (byte)0 }, 0);
            return length;
        }
        [Obsolete("不再使用NetMQMessage解析TLS协议RecordLayer层")]
        private static void GetProtocolVersion(byte[] bytes, ref int offset, NetMQMessage sslMessage)
        {
            byte[] protocolVersionBytes = new byte[Constants.PROTOCOL_VERSION_LENGTH];
            //get protocol version
            Buffer.BlockCopy(bytes, offset, protocolVersionBytes, 0, Constants.PROTOCOL_VERSION_LENGTH);
            sslMessage.Append(protocolVersionBytes);
            offset += Constants.PROTOCOL_VERSION_LENGTH;
        }
        [Obsolete("不再使用NetMQMessage解析TLS协议RecordLayer层")]
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
        [Obsolete("不再使用NetMQMessage解析TLS协议RecordLayer层")]
        private static void GetClientHelloLayer(HandshakeType handshakeType, byte[] bytes, ref int offset, NetMQMessage sslMessage)
        {
            int length = GetHandShakeContentLength(bytes, ref offset, sslMessage);
            GetProtocolVersion(bytes, ref offset, sslMessage);
            GetRandom(bytes, ref offset, sslMessage);
            GetSessionId(bytes, ref offset, sslMessage);

            byte[] cipherSuiteslengthBytes = new byte[Constants.CIPHER_SUITES_LENGTH];
            //get Cipher Suites Length version
            Buffer.BlockCopy(bytes, offset, cipherSuiteslengthBytes, 0, Constants.CIPHER_SUITES_LENGTH);
            sslMessage.Append(cipherSuiteslengthBytes);
            offset += Constants.CIPHER_SUITES_LENGTH;
            int cipherSuiteslength = BitConverter.ToUInt16(new []{cipherSuiteslengthBytes[1], cipherSuiteslengthBytes[0] }, 0);

            byte[] cipherSuitesBytes = new byte[cipherSuiteslength];
            //get Cipher Suites version
            Buffer.BlockCopy(bytes, offset, cipherSuitesBytes, 0, cipherSuiteslength);
            sslMessage.Append(cipherSuitesBytes);
            offset += cipherSuiteslength;
            //压缩长度1个字节
            byte[] compressionMethodLengthBytes = new byte[Constants.COMPRESSION_MENTHOD_LENGTH];
            //get Cipher Suites Length version
            Buffer.BlockCopy(bytes, offset, compressionMethodLengthBytes, 0, Constants.COMPRESSION_MENTHOD_LENGTH);
            sslMessage.Append(compressionMethodLengthBytes);
            offset += Constants.COMPRESSION_MENTHOD_LENGTH;
            int compressionMethodLength = (int)compressionMethodLengthBytes[0];
            byte[] compressionMethodBytes = new byte[compressionMethodLength];
            //get Cipher Suites version
            Buffer.BlockCopy(bytes, offset, compressionMethodBytes, 0, compressionMethodLength);
            offset += compressionMethodLength;
            sslMessage.Append(compressionMethodBytes);
            
            byte[] extensionsLengthBytes = new byte[Constants.EXTENSIONS_LENTGH];
            //get Cipher Suites Length version
            Buffer.BlockCopy(bytes, offset, extensionsLengthBytes, 0, Constants.EXTENSIONS_LENTGH);
            sslMessage.Append(extensionsLengthBytes);
            offset += Constants.EXTENSIONS_LENTGH;
            int extensioLength = BitConverter.ToUInt16(new[] { extensionsLengthBytes[1], extensionsLengthBytes[0] }, 0);

            byte[] extensionsBytes = new byte[extensioLength];
            //get Cipher Suites version
            Buffer.BlockCopy(bytes, offset, extensionsBytes, 0, extensioLength);
            sslMessage.Append(extensionsBytes);
            offset += extensioLength;
        }

        [Obsolete("不再使用NetMQMessage解析TLS协议RecordLayer层")]
        private static void GetSessionId(byte[] bytes, ref int offset, NetMQMessage sslMessage)
        {
            byte[] sessionIdLengthBytes = new byte[Constants.SESSION_ID_LENGTH];
            //get random version
            Buffer.BlockCopy(bytes, offset, sessionIdLengthBytes, 0, Constants.SESSION_ID_LENGTH);
            sslMessage.Append(sessionIdLengthBytes);
            offset += Constants.SESSION_ID_LENGTH;
            int length = (int)sessionIdLengthBytes[0];
            byte[] sessionIdBytes = new byte[length];
            Buffer.BlockCopy(bytes, offset, sessionIdBytes, 0, length);
            offset += length;
            sslMessage.Append(sessionIdBytes);
        }

        /// <summary>
        /// 解析ServerHello格式
        /// </summary>
        /// <param name="handshakeType"></param>
        /// <param name="bytes"></param>
        /// <param name="sslMessage"></param>
        [Obsolete("不再使用NetMQMessage解析TLS协议RecordLayer层")]
        private static int GetServerHelloLayer(HandshakeType handshakeType, byte[] bytes, ref int offset, NetMQMessage sslMessage)
        {
            int length = GetHandShakeContentLength(bytes, ref offset, sslMessage);

            GetProtocolVersion(bytes, ref offset, sslMessage);

            GetRandom(bytes, ref offset, sslMessage);

            GetSessionId(bytes, ref offset, sslMessage);

            byte[] cipherSuiteBytes = new byte[Constants.CIPHER_SUITE_LENGTH];
            //get Cipher Suites Length version
            Buffer.BlockCopy(bytes, offset, cipherSuiteBytes, 0, Constants.CIPHER_SUITE_LENGTH);
            sslMessage.Append(cipherSuiteBytes);
            offset += Constants.CIPHER_SUITE_LENGTH;
            //压缩方法
            byte[] compressionMethodBytes = new byte[Constants.COMPRESSION_MENTHOD];
            //get Cipher Suites Length version
            Buffer.BlockCopy(bytes, offset, compressionMethodBytes, 0, Constants.COMPRESSION_MENTHOD);
            sslMessage.Append(compressionMethodBytes);
            offset += Constants.COMPRESSION_MENTHOD;
            return offset;
        }

        /// <summary>
        /// 解析Certificate格式
        /// </summary>
        /// <param name="handshakeType"></param>
        /// <param name="bytes"></param>
        /// <param name="sslMessage"></param>
        [Obsolete("不再使用NetMQMessage解析TLS协议RecordLayer层")]
        private static void GetCertificateLayer(HandshakeType handshakeType, byte[] bytes, ref int offset, NetMQMessage sslMessage)
        {
            int length = GetHandShakeContentLength(bytes, ref offset, sslMessage);

            int start = offset;

            byte[] certificatesLengthBytes = new byte[Constants.CERTIFICATE_LENGTH];
            //get hand shake content length
            Buffer.BlockCopy(bytes, offset, certificatesLengthBytes, 0, Constants.CERTIFICATE_LENGTH);
            sslMessage.Append(certificatesLengthBytes);
            start += Constants.CERTIFICATE_LENGTH;

            int certificatesLength = BitConverter.ToInt32(new byte[] { certificatesLengthBytes[2], certificatesLengthBytes[1], certificatesLengthBytes[0], 0 }, 0);

            //目前只有一个证书
            //while (start < bytes.Length)
            //{
            byte[] certificateLengthBytes = new byte[Constants.CERTIFICATE_LENGTH];
            //get hand shake content length
            Buffer.BlockCopy(bytes, start, certificateLengthBytes, 0, Constants.CERTIFICATE_LENGTH);
            sslMessage.Append(certificateLengthBytes);
            //暂时只加载第一个证书
            int certificateLength = BitConverter.ToInt32(new byte[] {certificateLengthBytes[2], certificateLengthBytes[1], certificateLengthBytes[0] ,0}, 0);
            start += Constants.CERTIFICATE_LENGTH;
            byte[] certificateBytes = new byte[certificateLength];
            //get Cipher Suites Length version
            Buffer.BlockCopy(bytes, start, certificateBytes, 0, certificateLength);
            sslMessage.Append(certificateBytes);
            //}
            //加上总长度，多个证书不加载后面的证书，
            //length包含了Constants.CERTIFICATE_LENGTH，前面为了取证书偏移了一次。
            offset += length;
        }
        [Obsolete("不再使用NetMQMessage解析TLS协议RecordLayer层")]
        private static void GetServerHelloDoneLayer(HandshakeType handshakeType, byte[] bytes, ref int offset, NetMQMessage sslMessage)
        {
            byte[] handShakeContentLengthBytes= new byte[Constants.HAND_SHAKE_LENGTH];
            //get hand shake content length
            Buffer.BlockCopy(bytes, offset, handShakeContentLengthBytes, 0, Constants.HAND_SHAKE_LENGTH);
            sslMessage.Append(handShakeContentLengthBytes);
            offset += Constants.HAND_SHAKE_LENGTH;
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
        [Obsolete("不再使用NetMQMessage解析TLS协议RecordLayer层")]
        private static void GetClientKeyExchangeLayer(HandshakeType handshakeType, byte[] bytes, ref int offset, NetMQMessage sslMessage)
        {
            int length = GetHandShakeContentLength(bytes, ref offset, sslMessage);
            byte[] keyLengthBytes = new byte[Constants.RSA_KEY_LENGTH];
            //get hand shake content length
            Buffer.BlockCopy(bytes, offset, keyLengthBytes, 0, Constants.RSA_KEY_LENGTH);
            sslMessage.Append(keyLengthBytes);
            offset += Constants.RSA_KEY_LENGTH;

            byte[] clientKeyExchangeBytes = new byte[length - Constants.RSA_KEY_LENGTH];
            //get master key 
            Buffer.BlockCopy(bytes, offset, clientKeyExchangeBytes, 0, length - Constants.RSA_KEY_LENGTH);
            sslMessage.Append(clientKeyExchangeBytes);
            offset += length - Constants.RSA_KEY_LENGTH;
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
        [Obsolete("不再使用NetMQMessage解析TLS协议RecordLayer层")]
        private static void GetFinishLayer(HandshakeType handshakeType, byte[] bytes, ref int offset, NetMQMessage sslMessage)
        {
            byte[] verifyDataBytes = new byte[bytes.Length - offset];
            //get master key length
            Buffer.BlockCopy(bytes, offset, verifyDataBytes, 0, bytes.Length - offset);
            sslMessage.Append(verifyDataBytes);
            offset += verifyDataBytes.Length;
        }
        #endregion
    }
}
