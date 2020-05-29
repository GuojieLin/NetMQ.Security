using NetMQ.Security.Enums;
using System;
using System.Collections.Generic;

namespace NetMQ.Security.TLS12.HandshakeMessages
{
    /// <summary>
    /// The ServerHelloMessage is a HandshakeMessage with a <see cref="HandshakeType"/>of ServerHello.
    /// It holds a RandomNumber and a <see cref="CipherSuite"/>, both of which are gleaned from
    /// a NetMQMessage in the override of SetFromNetMQMessage.
    /// </summary>
    internal class ServerHelloMessage : HandshakeMessage
    {
        public ProtocolVersion Version { get; set; }
        /// <summary>
        /// Get the part of the handshake-protocol that this HandshakeMessage represents
        /// - in this case, ServerHello.
        /// </summary>
        public override HandshakeType HandshakeType => HandshakeType.ServerHello;

        /// <summary>
        /// Get or set the Random-Number that is a part of the handshake-protocol, as a byte-array.
        /// </summary>
        public byte[] Random { get; set; }
        public byte[] SessionID { get; set; }

        /// <summary>
        /// Get or set the byte that specifies the cipher-suite to be used.
        /// </summary>
        public CipherSuite CipherSuite { get; set; }

        /// <summary>
        /// <![CDATA[
        /// Handshake Protocol: Server Hello
        ///     Handshake Type: Server Hello(2)
        /// Length: 70
        /// Version: TLS 1.2 (0x0303)
        /// Random: 5ece1807d92aeb81c1b93492cdc904dfbbd711926b1ffbde…
        ///     GMT Unix Time: May 27, 2020 15:34:31.000000000 中国标准时间
        ///     Random Bytes: d92aeb81c1b93492cdc904dfbbd711926b1ffbde8291a525…
        /// Session ID Length: 32
        /// Session ID: 5ece1807eae276e745c3548e61aec6726827b7108906ceb7…
        /// Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA(0x002f)
        /// Compression Method: null (0)
        /// ]]>
        /// </summary>
        /// <param name="buffer"></param>
        public override void LoadFromByteBuffer(ReadonlyBuffer<byte> buffer)
        {
            int offset = 0;
            Version = (ProtocolVersion)buffer[offset, Constants.PROTOCOL_VERSION_LENGTH];
            offset += Constants.PROTOCOL_VERSION_LENGTH;
            // get the random number
            Random = buffer[offset, Constants.RANDOM_LENGTH];
            offset += Constants.RANDOM_LENGTH;
            byte[] sessionIdLengthBytes = buffer[offset, Constants.SESSION_ID_LENGTH];
            offset += Constants.SESSION_ID_LENGTH;
            int length = (int)sessionIdLengthBytes[0];
            byte[] sessionIdBytes = new byte[length];
            SessionID = buffer[offset, length];
            offset += length;
            // get the cipher-suites
            CipherSuite = (CipherSuite)buffer[offset+1];
            offset += Constants.CIPHER_SUITE_LENGTH;
            //压缩方法
            //compressionMethodLength buffer[Constants.COMPRESSION_MENTHOD_LENGTH]
        }

        public override byte[] ToBytes()
        {
            return this;
        }
        public static implicit operator byte[] (ServerHelloMessage message)
        {
            int sum = 0;
            List<byte[]> list = new List<byte[]>(10);
            sum += Add(message.Version, list);
            sum += Add(message.Random, list);
            sum += Add(new byte[] { (byte)message.SessionID.Length }, list);
            sum += Add(message.SessionID, list);
            sum += Add(new byte[] { 0, (byte)message.CipherSuite }, list);
            //压缩方法
            sum += Add(new byte[] { 0 }, list);
            return ByteArrayListToByteArray(list, sum);
        }
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
            if (message.FrameCount != 5)
            {
                throw new NetMQSecurityException(NetMQSecurityErrorCode.InvalidFramesCount, "Malformed message");
            }

            // Get the random number
            NetMQFrame randomNumberFrame = message.Pop();
            Random = randomNumberFrame.ToByteArray();
            NetMQFrame sessionIdLengthFrame = message.Pop();
            NetMQFrame sessionIdFrame = message.Pop();
            SessionID = sessionIdFrame.ToByteArray();
            // Get the cipher suite
            NetMQFrame cipherSuiteFrame = message.Pop();
            CipherSuite = (CipherSuite)cipherSuiteFrame.Buffer[1];

            NetMQFrame compressionMethod = message.Pop();

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
            NetMQMessage message = AddHandShakeType();
            message.Append(Random);
            message.Append(new byte[] { (byte)SessionID.Length });
            message.Append(SessionID);
            message.Append(new byte[] { 0, (byte)CipherSuite });

            var handShakeType = message.Pop();
            var random = message.Pop();
            message.Push(random);
            message.Push(Version);
            message.Append(new byte[1] { 0 });
            InsertLength(message);
            message.Push(handShakeType);
            return message;
        }
    }
}
