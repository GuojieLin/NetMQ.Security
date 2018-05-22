using NetMQ.Security.V0_1.HandshakeMessages;
using System;
using System.Diagnostics;

namespace NetMQ.Security.V0_2.HandshakeMessages
{
    /// <summary>
    /// The ClientHelloMessage is a HandshakeMessage with a HandshakeType of ClientHello.
    /// It holds a list denoting which CipherSuites are available and a RandomNumber property,
    /// and overrides SetFromNetMQMessage and ToNetMQMessage to read/write those
    /// from the frames of a NetMQMessage.
    /// </summary>
    internal class ClientHelloMessage : V0_1.HandshakeMessages.ClientHelloMessage
    {
        protected override byte[] Version { get { return new byte[] { 3, 3 }; } }
        /// <summary>
        /// Remove the three frames from the given NetMQMessage, interpreting them thusly:
        /// 1. a byte with the HandshakeType, presumed here to be ClientHello,
        /// 2. a byte-array containing the RandomNumber,
        /// 3. a byte-array with the list of CipherSuites.
        /// </summary>
        /// <param name="message">a NetMQMessage - which must have 2 frames</param>
        /// <exception cref="NetMQSecurityException"><see cref="NetMQSecurityErrorCode.InvalidFramesCount"/>: FrameCount must be 3.</exception>
        public override void SetFromNetMQMessage(NetMQMessage message)
        {
            RemoteHandShakeType(message);

            NetMQFrame versionFrame = message.Pop();
            NetMQFrame lengthFrame = message.Pop();
            InnerSetFromNetMQMessage(message);
        }

        /// <summary>
        /// Return a new NetMQMessage that holds three frames:
        /// 1. a frame with a single byte representing the HandshakeType, which is ClientHello,
        /// 2. a frame containing the RandomNumber,
        /// 3. a frame containing the list of CipherSuites.
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