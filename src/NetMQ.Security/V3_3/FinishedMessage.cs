using NetMQ.Security.V0_1.HandshakeMessages;
using System.Diagnostics;

namespace NetMQ.Security.V3_3.HandshakeMessages
{
    /// <summary>
    /// The FinishedMessage is a HandshakeMessage with a HandshakeType of Finished.
    /// It holds a VerificationData property and a VerificationDataLength constant.
    /// </summary>
    internal class FinishedMessage : V0_1.HandshakeMessages.FinishedMessage
    {
        /// <summary>
        /// Remove the two frames from the given NetMQMessage, interpreting them thusly:
        /// 1. a byte with the HandshakeType,
        /// 2. a byte-array containing the verification data - used to verify the integrity of the content.
        /// </summary>
        /// <param name="message">a NetMQMessage - which must have 2 frames</param>
        /// <exception cref="NetMQSecurityException"><see cref="NetMQSecurityErrorCode.InvalidFramesCount"/>: FrameCount must be 1.</exception>
        public override void SetFromNetMQMessage(NetMQMessage message)
        {
            RemoteHandShakeType(message);
            NetMQFrame lengthFrame = message.Pop();
            InnerSetFromNetMQMessage(message);
        }

        /// <summary>
        /// Return a new NetMQMessage that holds two frames:
        /// 1. a frame with a single byte representing the HandshakeType,
        /// 2. a frame containing the verification data.
        /// </summary>
        /// <returns>the resulting new NetMQMessage</returns>
        public override NetMQMessage ToNetMQMessage()
        {
            NetMQMessage message = base.ToNetMQMessage();
            InsertLength(message);
            return message;
        }
    }
}
