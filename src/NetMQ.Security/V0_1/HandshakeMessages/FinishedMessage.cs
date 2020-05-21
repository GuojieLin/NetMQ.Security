namespace NetMQ.Security.V0_1.HandshakeMessages
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
        /// Return a new NetMQMessage that holds two frames:
        /// 1. a frame with a single byte representing the HandshakeType,
        /// 2. a frame containing the verification data.
        /// </summary>
        /// <returns>the resulting new NetMQMessage</returns>
        public override NetMQMessage ToNetMQMessage()
        {
            NetMQMessage message = AddHandShakeType();
            message.Append(VerifyData);

            return message;
        }
    }
}
