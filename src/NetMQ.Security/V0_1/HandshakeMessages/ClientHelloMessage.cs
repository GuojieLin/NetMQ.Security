﻿using System;

namespace NetMQ.Security.V0_1.HandshakeMessages
{
    /// <summary>
    /// The ClientHelloMessage is a HandshakeMessage with a HandshakeType of ClientHello.
    /// It holds a list denoting which CipherSuites are available and a RandomNumber property,
    /// and overrides SetFromNetMQMessage and ToNetMQMessage to read/write those
    /// from the frames of a NetMQMessage.
    /// </summary>
    internal class ClientHelloMessage : HandshakeMessage
    {
        protected virtual byte[] Version { get { return Constants.V0_1; } }
        /// <summary>
        /// Get or set the Random-Number that is a part of the handshake-protocol, as a byte-array.
        /// </summary>
        public byte[] RandomNumber { get; set; }
        public byte[] SessionID { get; set; }

        /// <summary>
        /// Get the part of the handshake-protocol that this HandshakeMessage represents
        /// - in this case a ClientHello.
        /// </summary>
        public override HandshakeType HandshakeType => HandshakeType.ClientHello;

        /// <summary>
        /// Get or set the list of CipherSuites that are indicated as being available in this phase of the handshake-protocol.
        /// This is an array of bytes.
        /// </summary>
        public CipherSuite[] CipherSuites { get; set; }

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
            // get the length of the cipher-suites array
            NetMQFrame ciphersLengthFrame = message.Pop();

            byte[] temp = new byte[2];
            temp[1] = ciphersLengthFrame.Buffer[0];
            temp[0] = ciphersLengthFrame.Buffer[1];
            int ciphersLength = BitConverter.ToInt16(temp, 0);

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
            NetMQMessage message = AddHandShakeType();
            message.Append(RandomNumber);

            var bytes = BitConverter.GetBytes(SessionID.Length);
            message.Append(new byte[1] { bytes[0] });
            //目前是空的，暂不支持sessionid
            message.Append(SessionID);

            bytes = BitConverter.GetBytes(CipherSuites.Length);
            message.Append(new byte[2] { bytes[1], bytes[0] });

            byte[] cipherSuitesBytes = new byte[2 * CipherSuites.Length];
            int bytesIndex = 0;

            foreach (CipherSuite cipherSuite in CipherSuites)
            {
                cipherSuitesBytes[bytesIndex++] = 0;
                cipherSuitesBytes[bytesIndex++] = (byte)cipherSuite;
            }

            message.Append(cipherSuitesBytes);

            return message;
        }
    }
}
