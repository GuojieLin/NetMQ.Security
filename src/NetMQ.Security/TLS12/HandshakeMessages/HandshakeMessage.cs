using NetMQ.Security.Enums;
using System;

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

        public virtual NetMQMessage ToNetMQMessage()
        {
            throw new NotImplementedException();
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
    }
}
