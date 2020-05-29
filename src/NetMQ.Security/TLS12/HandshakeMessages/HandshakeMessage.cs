using NetMQ.Security.Enums;
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

//C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.8 Tools>SN -p  F:\Study\Git\NetMQ.Security\NetMQ.snk F:\Study\Git\NetMQ.Security\NetMQ.pk.snk
//C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.8 Tools>SN -tp  F:\Study\Git\NetMQ.Security\NetMQ.pk.snk
//https://www.cnblogs.com/artech/archive/2010/10/06/1844721.html
//前签名需要公钥
[assembly: InternalsVisibleTo("NetMQ.Security.Tests,PublicKey=0024000004800000940000000602000000240000525341310004000001000100c90e1ebf352af7132744cbb228ff09b10d7d758048085a392c57540a48f08321db8e92bc5605fb28a71339857b8d63752de08cb94943b292139b34616fd8a1f216a708c0bab9685e6114bf6b8d3cbba58c556fa0bc1f46970c8bd46e94c34b2c67f2220db09153f84fa0c39f5d341d84d59e3f0ccdfa033f4cfb9af501767fbb")]
namespace NetMQ.Security.TLS12.HandshakeMessages
{
    /// <summary>
    /// The abstract class HandshakeMessage holds a HandshakeType property and provides
    /// methods ToNetMQMessage and SetFromNetMQMessage, all intended to be overridden.
    /// </summary>
    internal abstract class HandshakeMessage
    {
        /// <summary>
        /// Get the part of the handshake-protocol that this HandshakeMessage represents.
        /// </summary>
        public abstract HandshakeType HandshakeType { get; }

        public virtual void SetFromNetMQMessage(NetMQMessage message)
        {
            throw new NotImplementedException();
        }
        public virtual void LoadFromByteBuffer(ReadonlyBuffer<byte> buffer)
        {
        }

        public virtual NetMQMessage ToNetMQMessage()
        {
            throw new NotImplementedException();
        }
        public virtual byte[] ToBytes()
        {
            return EmptyArray<byte>.Instance;
        }

        /// <summary>
        /// Return a new NetMQMessage that holds a frame containing only one byte containing the HandshakeType.
        /// </summary>
        /// <returns>the HandshakeType wrapped in a new NetMQMessage</returns>
        protected NetMQMessage AddHandShakeType()
        {
            NetMQMessage message = new NetMQMessage();
            message.Append(new[] { (byte)HandshakeType });

            return message;
        }
        public void InsertLength(NetMQMessage message)
        {
            byte[] lengthBytes= new byte[3];
            GetLength(lengthBytes, message);
            message.Push(lengthBytes);
        }
        /// <summary>
        /// 获取NetMQFrame数组的总字节数,填充到lengthBytes中。
        /// </summary>
        /// <returns>the resulting new NetMQMessage</returns>
        /// <exception cref="ArgumentException">handshake的数据大小不能超过65535,因为协议使用2个字节存储长度。</exception>
        public virtual void GetLength(byte[] lengthBytes ,NetMQMessage message)
        {
            message.GetLength(lengthBytes);
        }

        public static int Add(byte[] data,List<byte[]> list)
        {
            list.Add(data);
            return data.Length;
        }
        protected static byte[] ByteArrayListToByteArray(List<byte[]> list,int sum)
        {
            byte[] data = new byte[sum];
            int offset = 0;
            for (int i = 0; i < list.Count; i++)
            {
                Buffer.BlockCopy(list[i], 0, data, offset, list[i].Length);
                offset += list[i].Length;
            }
            return data;
        }
    }
}
