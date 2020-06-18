using NetMQ.Security.Layer;
using NetMQ.Security.TLS12;
using NetMQ.Security.TLS12.Layer;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace NetMQ.Security.Decoder
{
    /// <summary>
    /// 用于对字节缓存转换为TLS的RecordLayer格式
    /// </summary>
    internal class DecoderFactory
    {
        /// <summary>
        /// 解析报文,
        /// 若changeCipherSpec为true，则表示后续数据都是加密传输。
        /// 若changeCipherSpec为false，则表示后续数据都是明文传输。
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="changeCipherSpec">数据是否加密传输</param>
        /// <param name="offset">解析数据的偏移量</param>
        /// <param name="recordLayers">解析出的RecordLayer</param>
        /// <returns>解析数据成功返回true，数据长度不够解析失败，返回false</returns>
        internal static bool Decode(ReadonlyBuffer<byte> buffer, bool changeCipherSpec, out int offset, out RecordLayer recordLayer)
        {
#if DEBUG
            Debug.WriteLine("[Decode Buffer]Length:" + buffer.Length + "");
#endif
            //ContentType (1,handshake:22)
            //ProtocolVersion(2)
            //握手协议长度：(2)
            //握手协议数据
            if (buffer.Length < 5)
            {
                offset = 0;
                //长度至少要有5位
                recordLayer = null;
                return false;
            }
            //根据长度解析协议数据是否达到长度。
            TLSLength length = new TLSLength(buffer.Get(3, 2));
#if DEBUG
            Debug.WriteLine("[Decode Buffer] Record Layer Size:" + buffer.Length);
#endif
            //长度是否达到可解析 TLSRecord的长度
            if (buffer.Length - 5 < length.Length)
            {
#if DEBUG
                Debug.WriteLine("[Decode Buffer] buffer size less than " + buffer.Length);
#endif
                offset = 0;
                //长度不足，跳过解析。
                recordLayer = null;
                return false;
            }
            recordLayer = new RecordLayer();
            recordLayer.ContentType = (ContentType)buffer[0];
            recordLayer.ProtocolVersion = (ProtocolVersion)buffer[1, 2];
            recordLayer.Length = length;
            List<RecordProtocol> recordProtocols;
            //去除Record头部的剩余片段字节
            ReadonlyBuffer<byte> recordBuffer = buffer.Slice(5, length.Length);
            recordProtocols = Decode(recordLayer.ContentType, recordBuffer, changeCipherSpec);
            offset = 5 + length.Length;
            recordLayer.AddRecordProtocol(recordProtocols);
            return true;
        }

        /// <summary>
        /// 必须解析完成，或者抛出异常
        /// </summary>
        /// <param name="contentType"></param>
        /// <param name="buffer"></param>
        /// <param name="changeCipherSpec"></param>
        /// <returns></returns>
        internal static List<RecordProtocol> Decode(ContentType contentType, ReadonlyBuffer<byte> buffer, bool isEncrpyed)
        {
            #region record layer
            //可能会有多个握手层附在一个record层上
            //  TLSv1.2 Record Layer: Handshake Protocol: Client Hello
            //      Content Type: Handshake(22)
            //      Version: TLS 1.2(0x0303)
            //      Length: 130
            //      Handshake Protocol: Client Hello
            //  
            //Transport Layer Security
            //    TLSv1.2 Record Layer: Handshake Protocol: Multiple Handshake Messages
            //          Content Type: Handshake(22)
            //          Version: TLS 1.2(0x0303)
            //          Length: 946
            //          Handshake Protocol: Server Hello
            //          Handshake Protocol: Certificate
            //          Handshake Protocol: Server Hello Done
            //
            //Transport Layer Security
            //    TLSv1.2 Record Layer: Handshake Protocol: Server Hello
            //        Content Type: Handshake(22)
            //        Version: TLS 1.2(0x0303)
            //        Length: 74
            //        Handshake Protocol: Server Hello
            //    TLSv1.2 Record Layer: Handshake Protocol: Certificate
            //        Content Type: Handshake(22)
            //        Version: TLS 1.2(0x0303)
            //        Length: 868
            //        Handshake Protocol: Certificate
            //    TLSv1.2 Record Layer: Handshake Protocol: Server Hello Done
            //        Content Type: Handshake(22)
            //        Version: TLS 1.2(0x0303)
            //        Length: 4
            //        Handshake Protocol: Server Hello Done
            //Transport Layer Security
            //    TLSv1.2 Record Layer: Handshake Protocol: Client Key Exchange
            //        Content Type: Handshake(22)
            //        Version: TLS 1.2 (0x0303)
            //        Length: 134
            //        Handshake Protocol: Client Key Exchange
            //    TLSv1.2 Record Layer: Change Cipher Spec Protocol: Change Cipher Spec
            //        Content Type: Change Cipher Spec(20)
            //        Version: TLS 1.2 (0x0303)
            //        Length: 1
            //        Change Cipher Spec Message
            //    TLSv1.2 Record Layer: Handshake Protocol: Encrypted Handshake Message
            //        Content Type: Handshake(22)
            //        Version: TLS 1.2 (0x0303)
            //        Length: 64
            //        Handshake Protocol: Encrypted Handshake Message
            #endregion
            List<RecordProtocol> recordProtocols = new List<RecordProtocol>();
            if (isEncrpyed)
            {
                RecordProtocol protocol = DecodeEncryptedBuffer(contentType, buffer);
                recordProtocols.Add(protocol);
            }
            else
            {
                //未加密数据，可能有多个握手数据
                do
                {
                    RecordProtocol protocol = DecodeBuffer(contentType, buffer, isEncrpyed);
                    recordProtocols.Add(protocol);
                } while (buffer.Length > 0);
            }
            return recordProtocols;
        }
        /// <summary>
        /// 解析不加密的buffer数据。
        /// 根据各个协议对buffer进行格式解析。
        /// </summary>
        /// <param name="contentType"></param>
        /// <param name="buffer"></param>
        /// <returns></returns>
        private static RecordProtocol DecodeBuffer(ContentType contentType, ReadonlyBuffer<byte> buffer, bool changeCipherSpec)
        {
            RecordProtocol protocol;
            switch (contentType)
            {
                case ContentType.Handshake:
                    protocol = new HandshakeProtocol();
                    break;
                case ContentType.ChangeCipherSpec:
                    protocol = new ChangeCipherSpecProtocol();
                    break;
                case ContentType.Alert:
                    protocol = new AlertProtocol();
                    break;
                default:
                    throw new NetMQSecurityException(NetMQSecurityErrorCode.HandshakeUnexpectedMessage, "Unexpected Handshake Message");
            }
            int offset = DecodeToProtocol(contentType, protocol, buffer);
            //偏移长度，
            buffer.Position(offset);
            return protocol;
        }

        /// <summary>
        /// 将buffer加载到RecordProtocol中。
        /// </summary>
        /// <param name="contentType"></param>
        /// <param name="protocol"></param>
        /// <param name="buffer"></param>
        private static int DecodeToProtocol(ContentType contentType, RecordProtocol protocol, ReadonlyBuffer<byte> buffer)
        {
            //返回当前解析成功的Protocol的长度
            int offset = protocol.LoadFromByteBuffer(buffer);
#if DEBUG
            Debug.WriteLine("[" + contentType + "(Size:" + offset + ")]");
            if (protocol.HandShakeData != null)
            {
                Debug.WriteLine("[HandShakeData]" + BitConverter.ToString(protocol.HandShakeData) + ")]");
            }
#endif
            return offset;
        }

        /// <summary>
        /// 解析加密buffer
        /// 加密Buffer直接存储到HandshakeData中.后面需要通过数据解密后才可以处理。
        /// </summary>
        /// <param name="contentType"></param>
        /// <param name="buffer"></param>
        /// <returns></returns>
        private static RecordProtocol DecodeEncryptedBuffer(ContentType contentType, ReadonlyBuffer<byte> buffer)
        {
            RecordProtocol protocol;
            switch (contentType)
            {
                case ContentType.Handshake:
                    //加密
                    protocol = new HandshakeProtocol(true);
                    break;
                case ContentType.ApplicationData:
                    protocol = new ApplicationDataProtocol();
                    break;
                case ContentType.Alert:
                    protocol = new AlertProtocol(true);
                    break;
                default:
                    throw new NetMQSecurityException(NetMQSecurityErrorCode.HandshakeUnexpectedMessage, "Unexpected Encryped Data Content Type");
            }
            DecodeToProtocol(contentType, protocol, buffer);
            return protocol;
        }
    }
}
