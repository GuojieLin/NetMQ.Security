using NetMQ.Security.V0_1.HandshakeMessages;

namespace NetMQ.Security.V3_3.HandshakeMessages
{
    /// <summary>
    /// The ServerHelloDoneMessage is a HandshakeMessage with a HandshakeType of ServerHelloDone.
    /// </summary>
    internal class ServerHelloDoneMessage : V0_1.HandshakeMessages.ServerHelloDoneMessage
    {
        /// <summary>
        /// Remove the one frame from the given NetMQMessage, which shall contain one byte with the HandshakeType,
        /// presumed here to be ServerHelloDone.
        /// </summary>
        /// <param name="message">a NetMQMessage - which must have 1 frame</param>
        /// <exception cref="NetMQSecurityException"><see cref="NetMQSecurityErrorCode.InvalidFramesCount"/>: FrameCount must be 0.</exception>
        public override void SetFromNetMQMessage(NetMQMessage message)
        {
            RemoteHandShakeType(message);
            NetMQFrame lengthFrame = message.Pop();
            InnerSetFromNetMQMessage(message);
        }
        public override NetMQMessage ToNetMQMessage()
        {
            NetMQMessage message = base.ToNetMQMessage();
            InsertLength(message);
            return message;
        }
    }
}
