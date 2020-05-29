using NetMQ.Security.Enums;
using NetMQ.Security.Extensions;
using NetMQ.Security.TLS12.HandshakeMessages;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NetMQ.Security.TLS12.Layer
{
    public class HandshakeProtocol:RecordProtocol
    {
        public HandshakeType HandshakeType { get; set; }
        public TLSLength Length { get; set; }
        
        internal HandshakeMessage HandshakeMessage { get; set; }
        public HandshakeProtocol():base(false)
        {
        }
        public HandshakeProtocol(bool isEncrypted) : base(isEncrypted)
        {
        }
        /// <summary>
        /// 设置握手协议的握手消息，同时计算当前协议的明文报文保存于handshakedata中
        /// </summary>
        /// <param name="handshakeMessage"></param>
        internal void SetHandshakeMessage(HandshakeMessage handshakeMessage)
        {
            HandshakeMessage = handshakeMessage;
            HandshakeType = handshakeMessage.HandshakeType;
            HandShakeData = new ReadonlyBuffer<byte>(this);
        }
        /// <summary>
        /// <![CDATA[
        /// Handshake Protocol: Client Hello
        ///     Handshake Type: Client Hello (1)    1
        ///     Length: 126                         3
        ///     Handshake Protocol Mesasge
        /// ]]>
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public override int LoadFromByteBuffer(ReadonlyBuffer<byte> data)
        {
            //记录handshake内容，用于生成hash
            if (IsEncrypted)
            {
                return base.LoadFromByteBuffer(data);
            }
            //非加密需要解析
            HandshakeType = (HandshakeType)data[0];
            Length = new TLSLength(data[1, 3]);
            switch (HandshakeType)
            {
                case HandshakeType.HelloRequest:
                    HandshakeMessage = new HelloRequestMessage();
                    break;
                case HandshakeType.ClientHello:
                    HandshakeMessage = new ClientHelloMessage();
                    break;
                case HandshakeType.ServerHello:
                    HandshakeMessage = new ServerHelloMessage();
                    break;
                case HandshakeType.Certificate:
                    HandshakeMessage = new CertificateMessage();
                    break;
                case HandshakeType.ServerHelloDone:
                    HandshakeMessage = new ServerHelloDoneMessage();
                    break;
                case HandshakeType.ClientKeyExchange:
                    HandshakeMessage = new ClientKeyExchangeMessage();
                    break;
                case HandshakeType.Finished:
                    HandshakeMessage = new FinishedMessage();
                    break;
                default:
                    throw new NetMQSecurityException(NetMQSecurityErrorCode.HandshakeUnexpectedMessage, "Unexpected Handshake Type");
            }
            //需要解析的数字串。
            //解析出当前需要解析的数据。
            data = data.Slice(0, Length.Length + 4);
            //偏移4字节协议头解析握手报文
            HandshakeMessage.LoadFromByteBuffer(data.Slice(4));
            //返回解析长度
            //保存hash
            return base.LoadFromByteBuffer(data);
        }


        public static implicit operator byte[] (HandshakeProtocol message)
        {
            byte[] data;
            if (message.IsEncrypted)
            {
                //加密传输，返回加密数据。
                return message.HandShakeData;
            }
            else
            {

                data = message.HandshakeMessage.ToBytes();
            }
            //HandshakeType(1)|Length(3)|HandshakeMessage
            byte[] temp = new byte[4 + data.Length];
            temp[0] = (byte)message.HandshakeMessage.HandshakeType;
            byte[] lengthBytes = data.LengthToBigEndianBytes(Constants.HAND_SHAKE_LENGTH);
            Buffer.BlockCopy(lengthBytes, 0, temp, 1, lengthBytes.Length);
            Buffer.BlockCopy(data, 0, temp, 4, data.Length);
            return temp;
        }
        public override byte[] ToBytes()
        {
            return this;
        }
    }
}
