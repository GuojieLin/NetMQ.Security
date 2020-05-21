using NetMQ.Security.Extensions;
using System;
using System.Text;

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
        /// <summary>
        /// Get the part of the handshake-protocol that this HandshakeMessage represents
        /// - in this case a ClientHello.
        /// </summary>
        public override HandshakeType HandshakeType => HandshakeType.ClientHello;

        /// <summary>
        /// Get or set the list of CipherSuites that are indicated as being available in this phase of the handshake-protocol.
        /// This is an array of bytes.
        /// The cipher suite list, passed from the client to the server in the ClientHello message, contains the combinations of cryptographic
        /// algorithms supported by the client in order of the client's preference(favorite choice first).  
        /// Each cipher suite defines a key exchange algorithm, a bulk encryption algorithm(including secret key length), a MAC algorithm, and a PRF.
        /// The server will select a cipher suite or, if no acceptable choices are presented, return a handshake failure alert and close the connection.
        /// If the list contains cipher suites the server does not recognize, support, or wish to use, the server MUST ignore those cipher suites, and process the remaining ones as usual.
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
            this.SessionID = sessionIdFrame.ToByteArray();
            //若为空则需要初始话一个新的sessionid
            if (this.SessionID.Length == 0) this.SessionID = Encoding.ASCII.GetBytes(Guid.NewGuid().ToString("N"));

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

            if (SessionID == null) SessionID = new byte[0];
            message.Append(new byte[] { (byte)SessionID.Length });
            if (SessionID.Length > 0)
            {
                message.Append(SessionID);
            }
            int length = 2 * CipherSuites.Length;
            ////TODO:测试

            //length = 18;
            byte[] bytes = BitConverter.GetBytes(length);
            message.Append(new byte[2] { bytes[1], bytes[0] });

            byte[] cipherSuitesBytes = new byte[length];
            int bytesIndex = 0;

            foreach (CipherSuite cipherSuite in CipherSuites)
            {
                cipherSuitesBytes[bytesIndex++] = 0;
                cipherSuitesBytes[bytesIndex++] = (byte)cipherSuite;
            }
            ////TODO:测试

            //cipherSuitesBytes = "c0 2c c0 2b c0 2f c0 30 c0 13 c0 14 00 9c 00 2f 00 35".ConvertHexToByteArray();


            message.Append(cipherSuitesBytes);

            return message;
        }
    }
}
