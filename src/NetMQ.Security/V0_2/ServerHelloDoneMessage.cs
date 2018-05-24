using NetMQ.Security.V0_1.HandshakeMessages;

namespace NetMQ.Security.V0_2.HandshakeMessages
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
            NetMQFrame lengthFrame = message.Pop();
            base.SetFromNetMQMessage(message);
        }
        public override NetMQMessage ToNetMQMessage()
        {
            NetMQMessage message = base.ToNetMQMessage();
            var handShakeType = message.Pop();
            InsertLength(message);
            message.Push(handShakeType);
            return message;
        }
    }
}
