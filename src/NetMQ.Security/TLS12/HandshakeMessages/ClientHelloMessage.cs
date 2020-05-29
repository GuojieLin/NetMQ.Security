using NetMQ.Security.Enums;
using NetMQ.Security.Extensions;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace NetMQ.Security.TLS12.HandshakeMessages
{
    /// <summary>
    /// The ClientHelloMessage is a HandshakeMessage with a HandshakeType of ClientHello.
    /// It holds a list denoting which CipherSuites are available and a RandomNumber property,
    /// and overrides SetFromNetMQMessage and ToNetMQMessage to read/write those
    /// from the frames of a NetMQMessage.
    /// </summary>
    internal class ClientHelloMessage : HandshakeMessage
    {
        /// <summary>
        /// Get the part of the handshake-protocol that this HandshakeMessage represents
        /// - in this case a ClientHello.
        /// </summary>
        public override HandshakeType HandshakeType => HandshakeType.ClientHello;
        public ProtocolVersion Version { get; set; }
        /// <summary>
        /// Get or set the Random-Number that is a part of the handshake-protocol, as a byte-array.
        /// </summary>
        public byte[] Random { get; set; }
        /// <summary>
        ///  The ClientHello message includes a variable-length session identifier.
        ///  If not empty, the value identifies a session between the same client and server whose security parameters the client wishes to reuse.
        ///  The session identifier MAY be from an earlier connection, second option is useful if the client only wishes to update the random structures and derived values of a connection, 
        ///  and the third option makes it possible to establish several independent secure connections without repeating the full handshake protocol.
        ///  These independent connections may occur sequentially or simultaneously; 
        ///  a SessionID becomes valid when the handshake negotiating it completes with the exchange of Finished messages and persists until it is removed due to aging or because a fatal error was encountered on a connection associated with the session.
        ///  The actual contents of the SessionID are defined by the server.
        ///   Because the SessionID is transmitted without encryption or immediate MAC protection, servers MUST NOT place confidential information in session identifiers or let the contents of fake session identifiers cause any breach of security.  
        ///   (Note that the content of the handshake as a whole, including the SessionID, is protected by the Finished messages exchanged at the end of the handshake.)
        /// </summary>
        public byte[] SessionID { get; set; }

        public CipherSuite[] CipherSuites { get; set; }

        /// <summary>
        /// Get or set the list of CipherSuites that are indicated as being available in this phase of the handshake-protocol.
        /// This is an array of bytes.
        /// The cipher suite list, passed from the client to the server in the ClientHello message, contains the combinations of cryptographic
        /// algorithms supported by the client in order of the client's preference(favorite choice first).  
        /// Each cipher suite defines a key exchange algorithm, a bulk encryption algorithm(including secret key length), a MAC algorithm, and a PRF.
        /// The server will select a cipher suite or, if no acceptable choices are presented, return a handshake failure alert and close the connection.
        /// If the list contains cipher suites the server does not recognize, support, or wish to use, the server MUST ignore those cipher suites, and process the remaining ones as usual.
        /// <![CDATA[
        /// Handshake Protocol: Client Hello
        /// Handshake Type: Client Hello(1)
        /// Length: 126
        /// Version: TLS 1.2 (0x0303)
        /// Random: 5ecc6e7f10b4bf859526cc18b2b83d30be8880aa92d6d2a2…
        ///     GMT Unix Time: May 26, 2020 09:18:55.000000000 中国标准时间
        ///     Random Bytes: 10b4bf859526cc18b2b83d30be8880aa92d6d2a28cc7cdaa…
        /// Session ID Length: 0
        /// Cipher Suites Length: 18
        /// Cipher Suites(9 suites)
        ///     Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384(0xc02c)
        ///     Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256(0xc02b)
        ///     ...
        ///     Cipher Suite: TLS_RSA_WITH_AES_256_CBC_SHA(0x0035)
        /// Compression Methods Length: 1
        /// Compression Methods(1 method)
        ///     Compression Method: null (0)
        /// Extensions Length: 67
        /// Extension: supported_groups(len= 22)
        ///     Type: supported_groups(10)
        ///     Length: 22
        ///     Supported Groups List Length: 20
        ///     Supported Groups(10 groups)
        ///         Supported Group: secp256r1(0x0017)
        ///         ...
        /// Extension: ec_point_formats(len= 2)
        ///     Type: ec_point_formats(11)
        ///     Length: 2
        ///     EC point formats Length: 1
        ///     Elliptic curves point formats(1)
        ///         EC point format: uncompressed(0)
        /// Extension: signature_algorithms(len= 22)
        ///     Type: signature_algorithms(13)
        ///     Length: 22
        ///     Signature Hash Algorithms Length: 20
        ///     Signature Hash Algorithms(10 algorithms)
        ///         Signature Algorithm: ecdsa_secp521r1_sha512(0x0603)
        ///             Signature Hash Algorithm Hash: SHA512(6)
        ///             Signature Hash Algorithm Signature: ECDSA(3)
        ///         Signature Algorithm: rsa_pkcs1_sha512(0x0601)
        ///             Signature Hash Algorithm Hash: SHA512(6)
        ///             Signature Hash Algorithm Signature: RSA(1)
        ///         ...
        /// Extension: extended_master_secret(len= 0)
        ///     Type: extended_master_secret(23)
        ///     Length: 0
        /// Extension: renegotiation_info(len= 1)
        ///     Type: renegotiation_info(65281)
        ///     Length: 1
        ///     Renegotiation Info extension
        ///         Renegotiation info extension length: 0
        /// ]]>
        /// </summary>
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

            // get the length of the cipher-suites array
            byte[] temp = new byte[Constants.CIPHER_SUITES_LENGTH];
            temp[1] = buffer[offset];
            temp[0] = buffer[offset + 1];
            offset += Constants.CIPHER_SUITES_LENGTH;
            int ciphersLength = BitConverter.ToUInt16(temp, 0) / 2;

            // get the cipher-suites
            CipherSuites = new CipherSuite[ciphersLength];
            for (int i = 0; i < ciphersLength; i++)
            {
                //暂时只支持后面两个
                CipherSuites[i] = (CipherSuite)buffer[offset + i * 2 + 1];
            }
            offset += ciphersLength*2;

            var compressionMethodLength = (int)buffer[offset];
            offset += Constants.COMPRESSION_MENTHOD_LENGTH;
            var compressionMethod = buffer[offset, compressionMethodLength];
            offset += compressionMethodLength;
            var extensionsLengthBytes = buffer[offset, Constants.EXTENSIONS_LENTGH];
            offset += Constants.EXTENSIONS_LENTGH;
            int extensioLength = BitConverter.ToUInt16(new[] { extensionsLengthBytes[1], extensionsLengthBytes[0] }, 0);
            //buffer[offset, extensioLength];
            offset += extensioLength;
            Debug.Assert(offset == buffer.Length);
        }

        public override byte[] ToBytes()
        {
            return this;
        }
        public static implicit operator byte[] (ClientHelloMessage message)
        {
            int sum = 0;
            List<byte[]> list = new List<byte[]>(10);
            sum += Add(message.Version, list);
            sum += Add(message.Random, list);
            sum += Add(new byte[] { (byte)message.SessionID.Length }, list);
            sum += Add(message.SessionID, list);
            int length = 2 * message.CipherSuites.Length;
            byte[] bytes = BitConverter.GetBytes(length);
            sum += Add(new byte[2] { bytes[1], bytes[0] }, list);

            byte[] cipherSuitesBytes = new byte[length];
            int bytesIndex = 0;

            foreach (CipherSuite cipherSuite in message.CipherSuites)
            {
                cipherSuitesBytes[bytesIndex++] = 0;
                cipherSuitesBytes[bytesIndex++] = (byte)cipherSuite;
            }
            sum += Add(cipherSuitesBytes, list);
            //压缩方法长度,压缩方法,扩展长度
            sum += Add(new byte[] { 1, 0, 0, 0 }, list);
            return ByteArrayListToByteArray(list, sum);
        }

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
            if (message.FrameCount != 9)
            {
                throw new NetMQSecurityException(NetMQSecurityErrorCode.InvalidFramesCount, "Malformed message");
            }
            // get the random number
            NetMQFrame randomNumberFrame = message.Pop();
            Random = randomNumberFrame.ToByteArray();

            NetMQFrame sessionIdLengthFrame = message.Pop();
            NetMQFrame sessionIdFrame = message.Pop();
            SessionID = sessionIdFrame.ToByteArray();
            // get the length of the cipher-suites array
            NetMQFrame ciphersLengthFrame = message.Pop();

            byte[] temp = new byte[2];
            temp[1] = ciphersLengthFrame.Buffer[0];
            temp[0] = ciphersLengthFrame.Buffer[1];
            int ciphersLength = BitConverter.ToUInt16(temp, 0) / 2;

            // get the cipher-suites
            NetMQFrame ciphersFrame = message.Pop();
            CipherSuites = new CipherSuite[ciphersLength];
            for (int i = 0; i < ciphersLength; i++)
            {
                CipherSuites[i] = (CipherSuite)ciphersFrame.Buffer[i * 2 + 1];
            }
            NetMQFrame compressionMethodLength = message.Pop();
            NetMQFrame compressionMethod = message.Pop();
            NetMQFrame extensionsLength = message.Pop();
            NetMQFrame extensions = message.Pop();
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
            message.Append(Random);

            if (SessionID == null) SessionID = new byte[0];
            message.Append(new byte[] { (byte)SessionID.Length });
            if (SessionID.Length > 0)
            {
                message.Append(SessionID);
            }
            int length = 2 * CipherSuites.Length;
            byte[] bytes = BitConverter.GetBytes(length);
            message.Append(new byte[2] { bytes[1], bytes[0] });

            byte[] cipherSuitesBytes = new byte[length];
            int bytesIndex = 0;

            foreach (CipherSuite cipherSuite in CipherSuites)
            {
                cipherSuitesBytes[bytesIndex++] = 0;
                cipherSuitesBytes[bytesIndex++] = (byte)cipherSuite;
            }
            message.Append(cipherSuitesBytes);

            var handShakeType = message.Pop();
            var random = message.Pop();
            message.Push(random);
            message.Push(Version);
            //压缩方法长度
            message.Append(new byte[1] { 1 });
            //压缩方法
            message.Append(new byte[1] { 0 });
            message.Append(new byte[] { 0, 0 });
            InsertLength(message);
            message.Push(handShakeType);
            return message;
        }
    }
}
