using NetMQ.Security.V0_1.HandshakeMessages;
using System;
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
        protected override byte[] Version { get { return Constants.V3_3; } }
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
            if (message.FrameCount != 4)
            {
                throw new NetMQSecurityException(NetMQSecurityErrorCode.InvalidFramesCount, "Malformed message");
            }

            // Get the random number
            NetMQFrame randomNumberFrame = message.Pop();
            RandomNumber = randomNumberFrame.ToByteArray();

            NetMQFrame sessionIdLengthFrame = message.Pop();
            NetMQFrame sessionIdFrame = message.Pop();
            SessionID = sessionIdFrame.ToByteArray();
            // Get the cipher suite
            NetMQFrame cipherSuiteFrame = message.Pop();
            CipherSuite = (CipherSuite)cipherSuiteFrame.Buffer[1];

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
            var handShakeType = message.Pop();
            var random = message.Pop();
            var bytes = BitConverter.GetBytes(SessionID.Length);
            //目前是空的，暂不支持sessionid
            message.Push(SessionID);
            message.Push(new byte[1] { bytes[0] });
            message.Push(random);
            message.Push(Version);
            InsertLength(message);
            message.Push(handShakeType);
            return message;
        }
    }
}
