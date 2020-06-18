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
            var encryptedPreMasterSecretLength = message.EncryptedPreMasterSecret.LengthToBigEndianBytes(2);
            sum += Add(encryptedPreMasterSecretLength, list);
            sum += Add(message.EncryptedPreMasterSecret, list);
            return ByteArrayListToByteArray(list, sum);
        }
    }
}
