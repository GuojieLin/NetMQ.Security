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
        protected override byte[] Version { get { return Constants.V3_3 ; } }
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
            if (message.FrameCount != 5)
            {
                throw new NetMQSecurityException(NetMQSecurityErrorCode.InvalidFramesCount, "Malformed message");
            }
            // get the random number
            NetMQFrame randomNumberFrame = message.Pop();
            RandomNumber = randomNumberFrame.ToByteArray();

            NetMQFrame sessionIdLengthFrame = message.Pop();
            NetMQFrame sessionIdFrame = message.Pop();
            SessionID = sessionIdFrame.ToByteArray();
            // get the length of the cipher-suites array
            NetMQFrame ciphersLengthFrame = message.Pop();

            byte[] temp = new byte[2];
            temp[1] = ciphersLengthFrame.Buffer[0];
            temp[0] = ciphersLengthFrame.Buffer[1];
            int ciphersLength = BitConverter.ToUInt16(temp, 0) / 2 ;

            // get the cipher-suites
            NetMQFrame ciphersFrame = message.Pop();
            CipherSuites = new CipherSuite[ciphersLength];
            for (int i = 0; i < ciphersLength; i++)
            {
                CipherSuites[i] = (CipherSuite)ciphersFrame.Buffer[i * 2 + 1];
            }
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