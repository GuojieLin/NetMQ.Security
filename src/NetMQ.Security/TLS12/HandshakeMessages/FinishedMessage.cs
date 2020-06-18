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
    }
}
