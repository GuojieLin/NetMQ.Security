using NetMQ.Security.Enums;
using System;
using System.Collections.Generic;

namespace NetMQ.Security.TLS12.HandshakeMessages
{
    /// <summary>
    /// The FinishedMessage is a HandshakeMessage with a HandshakeType of Finished.
    /// It holds a VerificationData property and a VerificationDataLength constant.
    /// </summary>
    internal class FinishedMessage : HandshakeMessage
    {
        /// <summary>
        /// The number of bytes within the verification-data (which is a byte-array).
        /// </summary>
        public const int VerifyDataLength = 12;

        /// <summary>
        /// Get the part of the handshake-protocol that this HandshakeMessage represents
        /// - in this case, Finished.
        /// </summary>
        public override HandshakeType HandshakeType => HandshakeType.Finished;

        /// <summary>
        /// Get or set a byte-array that contains the verification data that is part of the finished-message.
        /// </summary>
        public byte[] VerifyData { get; set; }

        /// <summary>
        /// <![CDATA[
        /// Handshake Protocol: Encrypted Handshake Message
        /// ]]>
        /// </summary>
        /// <param name="buffer"></param>
        public override void LoadFromByteBuffer(ReadonlyBuffer<byte> buffer)
        {
            VerifyData = buffer[0, VerifyDataLength];
        }

        public override byte[] ToBytes()
        {
            return this;
        }
        public static implicit operator byte[] (FinishedMessage message)
        {
            return message.VerifyData;
        }
        /// <summary>
        /// Remove the two frames from the given NetMQMessage, interpreting them thusly:
        /// 1. a byte with the HandshakeType,
        /// 2. 3 byte with the Length,
        /// 3. a byte-array containing the verification data - used to verify the integrity of the content.
        /// </summary>
        /// <param name="message">a NetMQMessage - which must have 1 frames</param>
        /// <exception cref="NetMQSecurityException"><see cref="NetMQSecurityErrorCode.InvalidFramesCount"/>: FrameCount must be 1.</exception>
        public override void SetFromNetMQMessage(NetMQMessage message)
        {
            if (message.FrameCount != 1)
            {
                throw new NetMQSecurityException(NetMQSecurityErrorCode.InvalidFramesCount, "Malformed message");
            }

            if (message.First.BufferSize != 16)
            {
                throw new NetMQSecurityException(NetMQSecurityErrorCode.InvalidFrameLength, "Malformed message");
            }
            if ((HandshakeType)message.First.Buffer[0] != HandshakeType.Finished)
            {
                throw new NetMQSecurityException(NetMQSecurityErrorCode.HandshakeUnexpectedMessage, "Malformed message");
            }
            //小端
            byte[] lengthByte = new byte[] { message.First.Buffer[3], message.First.Buffer[2], message.First.Buffer[1], (byte)0 };
            int length = BitConverter.ToInt32(lengthByte, 0);
            if (length != 12)
            {
                throw new NetMQSecurityException(NetMQSecurityErrorCode.InvalidFrameLength, "Malformed message");
            }
            VerifyData = new byte[12];
            Buffer.BlockCopy(message.First.Buffer, 4, VerifyData, 0, VerifyData.Length);
        }
        /// <summary>
        /// Return a new NetMQMessage that holds two frames:
        /// 1. a frame with a single byte representing the HandshakeType,
        /// 2. a frame containing the verification data.
        /// </summary>
        /// <returns>the resulting new NetMQMessage</returns>
        public override NetMQMessage ToNetMQMessage()
        {
            NetMQMessage message = AddHandShakeType();
            message.Append(VerifyData);

            var handShakeType = message.Pop();
            InsertLength(message);
            message.Push(handShakeType);
            return message;
        }
    }
}
