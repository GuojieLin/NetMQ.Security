using NetMQ.Security.Extensions;
using NetMQ.Security.TLS12;
using NetMQ.Security.TLS12.Layer;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NetMQ.Security.Layer
{
    /// <summary>
    /// TLS协议是一个分层协议，第一层为TLS记录层协议(Record Layer Protocol)，该协议用于封装各种高级协议。
    /// 目前封装了4种协议：握手协议（Handshake Protocol）、改变密码标准协议（Change Cipher Spec Protocol）、应用程序数据协议（Application Data Protocol）和警报协议（Alert Protocol）。
    /// 记录层包含协议类型、版本号、长度、以及封装的高层协议内容。记录层头部为固定5字节大小。
    /// </summary>
    public class RecordLayer
    {
        /// <summary>
        /// 协议类型：1 byte
        /// </summary>
        public ContentType ContentType { get; set; }
        /// <summary>
        /// TLS1.2:0303 2byte
        /// </summary>
        public ProtocolVersion ProtocolVersion { get; set; }
        /// <summary>
        /// 长度：2byte TLS长度统一大端模式
        /// </summary>
        public TLSLength Length { get; set; }
        /// <summary>
        /// 子协议
        /// </summary>
        public List<RecordProtocol> RecordProtocols { get; set; }
        public RecordLayer(int capacity = 1)
        {
            RecordProtocols = new List<RecordProtocol>(capacity);
        }
        public void AddChangeCipherSpecProtocol(ChangeCipherSpecProtocol protocol)
        {
            ContentType = ContentType.ChangeCipherSpec;
            RecordProtocols.Add(protocol);
        }
        public void AddHandshake(HandshakeProtocol protocol)
        {
            ContentType = ContentType.Handshake;
            RecordProtocols.Add(protocol);
        }
        public void AddApplicationDataProtocol (ApplicationDataProtocol protocol)
        {
            ContentType = ContentType.ApplicationData;
            RecordProtocols.Add(protocol);
        }
        public void AddAlertProtocol(AlertProtocol protocol)
        {
            ContentType = ContentType.Alert;
            RecordProtocols.Add(protocol);
        }
        public void AddRecordProtocol(List<RecordProtocol> protocols)
        {
            RecordProtocols = protocols;
        }

        public static implicit operator byte[] (RecordLayer message)
        {
            List<byte[]> data = new List<byte[]>(message.RecordProtocols.Count);
            foreach(var recordProcotol in message.RecordProtocols)
            {
                data.Add(recordProcotol.ToBytes());
            }
            //HandshakeType(1)|Version(2)|Length(2)|HandshakeMessage
            int totalLength = data.Sum(d => d.Length);
            byte[] temp = new byte[5 + totalLength];
            temp[0] = (byte)message.ContentType;
            temp[1] = message.ProtocolVersion.Major;
            temp[2] = message.ProtocolVersion.Minor;
            byte[] lengthBytes = totalLength.ToBigEndianBytes(Constants.RECORD_LAYER_LENGTH);
            Buffer.BlockCopy(lengthBytes, 0, temp, Constants.CONTENT_TYPE_LENGTH + Constants.RECORD_LAYER_LENGTH, lengthBytes.Length);
            int offset = 5;
            foreach(byte[] item in data)
            {
                Buffer.BlockCopy(item, 0, temp, offset, item.Length);
                offset += item.Length;
            }
            return temp;
        }
    }
}
