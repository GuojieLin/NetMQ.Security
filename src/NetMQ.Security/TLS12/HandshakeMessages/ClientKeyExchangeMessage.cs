using NetMQ.Security.Enums;
using NetMQ.Security.Extensions;
using System;
using System.Collections.Generic;

namespace NetMQ.Security.TLS12.HandshakeMessages
{
    /// <summary>
    /// The ClientKeyExchangeMessage is a HandshakeMessage with a HandshakeType of ClientKeyExchange.
    /// It holds a EncryptedPreMasterSecret,
    /// and overrides SetFromNetMQMessage/ToNetMQMessage to read/write that
    /// from the frames of a <see cref="NetMQMessage"/>.
    /// </summary>
    internal class ClientKeyExchangeMessage : HandshakeMessage
    {
        /// <summary>
        /// The number of bytes within the EncryptedPreMasterSecret.
        /// </summary>
        public const int PreMasterSecretLength = 48;

        /// <summary>
        /// Get the part of the handshake-protocol that this HandshakeMessage represents
        /// - in this case a ClientKeyExchange.
        /// </summary>
        public override HandshakeType HandshakeType => HandshakeType.ClientKeyExchange;

        /// <summary>
        /// Get or set the 48-byte array that is the encrypted pre-master secret.
        /// </summary>
        public byte[] EncryptedPreMasterSecret { get; set; }

        /// <summary>
        /// <![CDATA[
        /// Handshake Protocol: Client Key Exchange
        ///      Handshake Type: Client Key Exchange(16)
        ///  Length: 130
        ///  RSA Encrypted PreMaster Secret
        ///      Encrypted PreMaster length: 128
        ///      Encrypted PreMaster: 5824d9ad49646385b44db6839f9452ad5b9abc3f77c8233b…

        /// ]]>
        /// </summary>
        /// <param name="buffer"></param>
        public override void LoadFromByteBuffer(ReadonlyBuffer<byte> buffer)
        {
            int offset = 0;
            byte[] keyLengthBytes = buffer[0, Constants.RSA_KEY_LENGTH];
            //get hand shake content length
            offset += Constants.RSA_KEY_LENGTH;

            int length = BitConverter.ToUInt16(new[] { buffer[1], buffer[0] }, 0);

            EncryptedPreMasterSecret = buffer[offset, length];
            //get master key 
            offset += length;
        }

        public override byte[] ToBytes()
        {
            return this;
        }
        public static implicit operator byte[] (ClientKeyExchangeMessage message)
        {
            int sum = 0;
            List<byte[]> list = new List<byte[]>(10);
            var encryptedPreMasterSecretLength = message.EncryptedPreMasterSecret.LengthToBytes(2);
            sum += Add(encryptedPreMasterSecretLength, list);
            sum += Add(message.EncryptedPreMasterSecret, list);
            return ByteArrayListToByteArray(list, sum);
        }
        /// <summary>
        /// Return a new NetMQMessage that holds two frames:
        /// 1. a frame with a single byte representing the HandshakeType, which is ClientKeyExchange,
        /// 2. a frame containing the EncryptedPreMasterSecret.
        /// </summary>
        /// <returns>the resulting new NetMQMessage</returns>
        public override NetMQMessage ToNetMQMessage()
        {
            NetMQMessage message = AddHandShakeType();

            var encryptedPreMasterSecretLength = BitConverter.GetBytes(EncryptedPreMasterSecret.Length);
            message.Append(new byte[] { encryptedPreMasterSecretLength[1], encryptedPreMasterSecretLength[0] });
            message.Append(EncryptedPreMasterSecret);
            var handShakeType = message.Pop();
            InsertLength(message);
            message.Push(handShakeType);
            return message;
        }

        /// <summary>
        /// Remove the two frames from the given NetMQMessage, interpreting them thusly:
        /// 1. a byte with the HandshakeType, assumed to be ClientKeyExchange
        /// 2. a byte-array containing the EncryptedPreMasterSecret.
        /// </summary>
        /// <param name="message">a NetMQMessage - which must have 2 frames</param>
        /// <exception cref="NetMQSecurityException"><see cref="NetMQSecurityErrorCode.InvalidFramesCount"/>: FrameCount must be 1.</exception>
        public override void SetFromNetMQMessage(NetMQMessage message)
        {
            if (message.FrameCount != 3)
            {
                throw new NetMQSecurityException(NetMQSecurityErrorCode.InvalidFramesCount, "Malformed message");
            }

            NetMQFrame lengthFrame = message.Pop();
            NetMQFrame encryptedPreMasterSecretLengthFrame = message.Pop();
            NetMQFrame preMasterSecretFrame = message.Pop();

            EncryptedPreMasterSecret = preMasterSecretFrame.ToByteArray();
        }
    }
}
