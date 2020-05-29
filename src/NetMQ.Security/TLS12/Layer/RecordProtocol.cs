using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NetMQ.Security.TLS12.Layer
{
    /// <summary>
    /// 目前封装了4种协议：握手协议（Handshake Protocol）、改变密码标准协议（Change Cipher Spec Protocol）、应用程序数据协议（Application Data Protocol）和警报协议（Alert Protocol）。
    /// 应用程序数据协议会加密
    /// 警报协议在改变密码标准协议以后发送时会加密。
    /// Finished握手协议会加密
    /// </summary>
    public class RecordProtocol
    {
        /// <summary>
        /// 是否加密
        /// 接收数据时加密数据会设置为加密，会先进行解密。加密数据保存到HandShakeData中。
        /// 发送数据时加密数据最后会设置该值为true，生成字节数据时若IsEncrypted为true，则原样返回HandShakeData
        /// </summary>
        public bool IsEncrypted { get; set; }
        /// <summary>
        /// 接收数据时，若数据加密保存的是加密数据
        /// 生成发送握手数据是，保存的是要发送的握手数据，用于hash计算。
        /// 若发送的是加密数据，先保存明文发送的握手数据，用于hash计算，然后保存的是加密后的数据，并设置IsEncrypted为true
        /// </summary>
        public ReadonlyBuffer<byte> HandShakeData { get; set; }
        public RecordProtocol(bool isEncrypted)
        {
            IsEncrypted = isEncrypted;
        }
        public virtual int LoadFromByteBuffer(ReadonlyBuffer<byte> data)
        {
            HandShakeData = data;
            return data.Length;
        }
        public virtual byte[] ToBytes()
        {
            throw new NotImplementedException();
        }
    }
}
