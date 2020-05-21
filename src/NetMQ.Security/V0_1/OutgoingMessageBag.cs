using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace NetMQ.Security.V0_1
{
    /// <summary>
    /// This class contains a list of NetMQMessages,
    /// and a SecureChannel to use when adding protocol messages to it.
    /// </summary>
    internal class OutgoingMessageBag
    {
        private readonly SecureChannel m_secureChannel;
        private readonly IList<NetMQMessage> m_messages;

        /// <summary>
        /// Create a new instance of an OutgoingMessageBag that will use the given SecureChannel.
        /// </summary>
        /// <param name="secureChannel">a SecureChannel object that will serve to encrypt the protocol messages</param>
        public OutgoingMessageBag(SecureChannel secureChannel)
        {
            m_secureChannel = secureChannel;
            m_messages = new List<NetMQMessage>();
        }

        /// <summary>
        /// Get the list of NetMQMessages that this OutgoingMessageBag is holding.
        /// </summary>
        public IEnumerable<NetMQMessage> Messages => m_messages;

        /// <summary>
        /// Add the given NetMQMessage to the list that this object holds, using the SecureChannel to
        /// encrypt and wrap it as a ChangeCipherSpec type of content.
        /// </summary>
        /// <param name="message">the NetMQMessage to add to the list that this object is holding</param>
        public void AddCipherChangeMessage(byte[] message)
        {
            byte[] bytes = m_secureChannel.WrapToRecordLayerMessage(ContentType.ChangeCipherSpec, message);
            NetMQMessage tlsMessage = new NetMQMessage();
            tlsMessage.Append(bytes);
            m_messages.Add(tlsMessage);
        }

        /// <summary>
        /// Add the given NetMQMessage to the list that this object holds, using the SecureChannel to
        /// encrypt and wrap it as a Handshake type of content.
        /// </summary>
        /// <param name="message">the NetMQMessage to add to the list that this object is holding</param>
        public void AddHandshakeMessage(NetMQMessage handshakeMessage)
        {
            byte[] bytes = new byte[handshakeMessage.Sum(f=>f.BufferSize)];
            int offset = 0;
            foreach (var frame in handshakeMessage)
            {
                Buffer.BlockCopy(frame.Buffer, 0, bytes, offset, frame.BufferSize);
                offset += frame.BufferSize;
            }
            AddHandshakeMessage(bytes);
        }
        public void AddHandshakeMessage(byte[] message)
        {
#if DEBUG
            Debug.WriteLine("[handshake(" + message.Length + ")]" + BitConverter.ToString(message));
#endif
            byte[] bytes = m_secureChannel.WrapToRecordLayerMessage(ContentType.Handshake, message);

#if DEBUG
            Debug.WriteLine("[record layer(" + message.Length + ")]:" + BitConverter.ToString(message));
#endif
            NetMQMessage tlsMessage = new NetMQMessage();
            tlsMessage.Append(bytes);
            m_messages.Add(tlsMessage);
        }
        /// <summary>
        /// Empty the list of NetMQMessages that this object holds.
        /// </summary>
        public void Clear()
        {
            m_messages.Clear();
        }
    }
}
