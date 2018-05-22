using NetMQ.Security.V0_1.HandshakeMessages;
using System.Diagnostics;

namespace NetMQ.Security.V0_2.HandshakeMessages
{
    /// <summary>
    /// The ServerHelloMessage is a HandshakeMessage with a <see cref="HandshakeType"/>of ServerHello.
    /// It holds a RandomNumber and a <see cref="CipherSuite"/>, both of which are gleaned from
    /// a NetMQMessage in the override of SetFromNetMQMessage.
    /// </summary>
    internal class ServerHelloMessage : V0_1.HandshakeMessages.ServerHelloMessage
    {
        protected override byte[] Version { get { return new byte[] { 3, 3 }; } }
        /// <summary>
        /// Remove the three frames from the given NetMQMessage, interpreting them thusly:
        /// 1. a byte with the <see cref="HandshakeType"/>,
        /// 2. RandomNumber (a byte-array),
        /// 3. a 2-byte array with the <see cref="CipherSuite"/> in the 2nd byte.
        /// </summary>
        /// <param name="message">a NetMQMessage - which must have 3 frames</param>
        /// <exception cref="NetMQSecurityException"><see cref="NetMQSecurityErrorCode.InvalidFramesCount"/>: FrameCount must be 2.</exception>
        public override void SetFromNetMQMessage(NetMQMessage message)
        {
            RemoteHandShakeType(message);

            NetMQFrame versionFrame = message.Pop();
            NetMQFrame lengthFrame = message.Pop();
            InnerSetFromNetMQMessage(message);
        }

        /// <summary>
        /// Return a new NetMQMessage that holds three frames:
        /// 1. contains a byte with the <see cref="HandshakeType"/>,
        /// 2. contains the RandomNumber (a byte-array),
        /// 3. contains a 2-byte array containing zero, and a byte representing the CipherSuite.
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
