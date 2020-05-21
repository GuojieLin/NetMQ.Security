using NetMQ.Security.V0_1.HandshakeMessages;
using System;
using System.Diagnostics;

namespace NetMQ.Security.V0_2.HandshakeMessages
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
            if((HandshakeType)message.First.Buffer[0]!= HandshakeType.Finished)
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
            NetMQMessage message = base.ToNetMQMessage();
            var handShakeType = message.Pop();
            InsertLength(message);
            message.Push(handShakeType);
            return message;
        }
    }
}
