using NetMQ.Security.Enums;

namespace NetMQ.Security.TLS12.HandshakeMessages
{
    /// <summary>
    /// The ServerHelloDoneMessage is a HandshakeMessage with a HandshakeType of ServerHelloDone.
    /// </summary>
    internal class ServerHelloDoneMessage : HandshakeMessage
    {
        /// <summary>
        /// Get the part of the handshake-protocol that this HandshakeMessage represents
        /// - in this case, ServerHelloDone.
        /// </summary>
        public override HandshakeType HandshakeType => HandshakeType.ServerHelloDone;


        /// <summary>
        /// <![CDATA[
        /// Handshake Protocol: Server Hello Done
        /// Handshake Type: Server Hello Done(14)
        /// Length: 0
        /// ]]>
        /// </summary>
        /// <param name="buffer"></param>
        public override void LoadFromByteBuffer(ReadonlyBuffer<byte> buffer)
        {
        }

        public override byte[] ToBytes()
        {
            return this;
        }
        public static implicit operator byte[] (ServerHelloDoneMessage message)
        {
            return EmptyArray<byte>.Instance;
        }
    }
}
