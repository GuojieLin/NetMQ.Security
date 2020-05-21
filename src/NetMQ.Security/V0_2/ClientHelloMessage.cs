﻿using NetMQ.Security.Extensions;
using NetMQ.Security.V0_1.HandshakeMessages;
using System;
using System.Diagnostics;

namespace NetMQ.Security.V0_2.HandshakeMessages
{
    /// <summary>
    /// The ClientHelloMessage is a HandshakeMessage with a HandshakeType of ClientHello.
    /// It holds a list denoting which CipherSuites are available and a RandomNumber property,
    /// and overrides SetFromNetMQMessage and ToNetMQMessage to read/write those
    /// from the frames of a NetMQMessage.
    /// 
    ///  When this message will be sent:
    ///    When a client first connects to a server, it is required to send
    ///    the ClientHello as its first message.The client can also send a
    ///      ClientHello in response to a HelloRequest or on its own initiative
    ///      in order to renegotiate the security parameters in an existing
    ///      connection.
    ///   Structure of this message:
    ///      The ClientHello message includes a random structure, which is used
    ///      later in the protocol.
    ///         struct {
    ///             uint32 gmt_unix_time;
    ///    opaque random_bytes[28];
    ///}
    ///Random;
    ///      gmt_unix_time
    ///         The current time and date in standard UNIX 32-bit format
    ///         (seconds since the midnight starting Jan 1, 1970, UTC, ignoring
    ///         leap seconds) according to the sender's internal clock.  Clocks
    ///         are not required to be set correctly by the basic TLS protocol;
    ///higher-level or application protocols may define additional
    ///requirements.Note that, for historical reasons, the data
    ///element is named using GMT, the predecessor of the current
    ///worldwide time base, UTC.
    ///random_bytes
    ///         28 bytes generated by a secure random number generator.
    ///   The ClientHello message includes a variable-length session
    ///   identifier.If not empty, the value identifies a session between the
    ///   same client and server whose security parameters the client wishes to
    ///   reuse.The session identifier MAY be from an earlier connection,
    ///   this connection, or from another currently active connection.  The
    ///   second option is useful if the client only wishes to update the
    ///   random structures and derived values of a connection, and the third
    ///   option makes it possible to establish several independent secure
    ///   connections without repeating the full handshake protocol.These
    ///   independent connections may occur sequentially or simultaneously; a
    ///   SessionID becomes valid when the handshake negotiating it completes
    ///   with the exchange of Finished messages and persists until it is
    ///   removed due to aging or because a fatal error was encountered on a
    ///   connection associated with the session.The actual contents of the
    ///   SessionID are defined by the server.
    ///      opaque SessionID<0..32>;
    ///Warning: Because the SessionID is transmitted without encryption or
    ///   immediate MAC protection, servers MUST NOT place confidential
    ///   information in session identifiers or let the contents of fake
    ///   session identifiers cause any breach of security.  (Note that the
    ///   content of the handshake as a whole, including the SessionID, is
    ///   protected by the Finished messages exchanged at the end of the
    ///   handshake.)
    ///   The cipher suite list, passed from the client to the server in the
    ///   ClientHello message, contains the combinations of cryptographic
    ///   algorithms supported by the client in order of the client's
    ///   preference(favorite choice first).  Each cipher suite defines a key
    ///   exchange algorithm, a bulk encryption algorithm(including secret key
    ///   length), a MAC algorithm, and a PRF.The server will select a cipher
    ///   suite or, if no acceptable choices are presented, return a handshake
    ///   failure alert and close the connection.If the list contains cipher
    ///   suites the server does not recognize, support, or wish to use, the
    ///   server MUST ignore those cipher suites, and process the remaining
    ///   ones as usual.
    ///      uint8 CipherSuite[2];    /* Cryptographic suite selector */
    ///The ClientHello includes a list of compression algorithms supported
    ///by the client, ordered according to the client's preference.
    ///      enum { null(0), (255) }
    ///CompressionMethod;
    ///      struct {
    ///          ProtocolVersion client_version;
    ///Random random;
    ///SessionID session_id;
    ///CipherSuite cipher_suites<2..2^16-2>;
    ///CompressionMethod compression_methods<1..2^8-1>;
    ///select(extensions_present)
    ///{
    ///              case false:
    ///                  struct { };
    ///              case true:
    ///                  Extension extensions<0..2^16-1>;
    ///          };
    ///      } ClientHello;
    ///   TLS allows extensions to follow the compression_methods field in an
    ///   extensions block.The presence of extensions can be detected by
    ///   determining whether there are bytes following the compression_methods
    ///   at the end of the ClientHello.Note that this method of detecting
    ///   optional data differs from the normal TLS method of having a
    ///   variable-length field, but it is used for compatibility with TLS
    ///   before extensions were defined.
    ///   client_version
    ///      The version of the TLS protocol by which the client wishes to
    ///      communicate during this session.This SHOULD be the latest
    ///      (highest valued) version supported by the client.  For this
    ///      version of the specification, the version will be 3.3 (see
    ///      Appendix E for details about backward compatibility).
    ///   random
    ///      A client-generated random structure.
    ///   session_id
    ///      The ID of a session the client wishes to use for this connection.
    ///      This field is empty if no session_id is available, or if the
    ///      client wishes to generate new security parameters.
    ///   cipher_suites
    ///      This is a list of the cryptographic options supported by the
    ///      client, with the client's first preference first.  If the
    ///      session_id field is not empty (implying a session resumption
    ///      request), this vector MUST include at least the cipher_suite from
    ///      that session.  Values are defined in Appendix A.5.
    ///   compression_methods
    ///      This is a list of the compression methods supported by the client,
    ///      sorted by client preference.  If the session_id field is not empty
    ///      (implying a session resumption request), it MUST include the
    ///      compression_method from that session.  This vector MUST contain,
    ///      and all implementations MUST support, CompressionMethod.null.
    ///      Thus, a client and server will always be able to agree on a
    ///      compression method.
    ///   extensions
    ///      Clients MAY request extended functionality from servers by sending
    ///      data in the extensions field.  The actual "Extension" format is
    ///      defined in Section 7.4.1.4.
    ///   In the event that a client requests additional functionality using
    ///   extensions, and this functionality is not supplied by the server, the
    ///   client MAY abort the handshake.  A server MUST accept ClientHello
    ///   messages both with and without the extensions field, and (as for all
    ///   other messages) it MUST check that the amount of data in the message
    ///   precisely matches one of these formats; if not, then it MUST send a
    ///   fatal "decode_error" alert.
    ///   After sending the ClientHello message, the client waits for a
    ///   ServerHello message.  Any handshake message returned by the server,
    ///   except for a HelloRequest, is treated as a fatal error.
    /// </summary>
    internal class ClientHelloMessage : V0_1.HandshakeMessages.ClientHelloMessage
    {
        protected override byte[] Version { get { return Constants.V3_3 ; } }
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
            RandomNumber = randomNumberFrame.ToByteArray();

            NetMQFrame sessionIdLengthFrame = message.Pop();
            NetMQFrame sessionIdFrame = message.Pop();
            SessionID = sessionIdFrame.ToByteArray();
            // get the length of the cipher-suites array
            NetMQFrame ciphersLengthFrame = message.Pop();

            byte[] temp = new byte[2];
            temp[1] = ciphersLengthFrame.Buffer[0];
            temp[0] = ciphersLengthFrame.Buffer[1];
            int ciphersLength = BitConverter.ToUInt16(temp, 0) / 2 ;

            // get the cipher-suites
            NetMQFrame ciphersFrame = message.Pop();
            CipherSuites = new CipherSuite[ciphersLength];
            for (int i = 0; i < ciphersLength; i++)
            {
                CipherSuites[i] = (CipherSuite)ciphersFrame.Buffer[i * 2 + 1];
            }
            NetMQFrame compressionMethodLength= message.Pop();
            NetMQFrame compressionMethod= message.Pop();
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
            NetMQMessage message = base.ToNetMQMessage();
            var handShakeType = message.Pop();
            var random = message.Pop();
            message.Push(random);
            message.Push(Version);
            //压缩方法长度
            message.Append(new byte[1] { 1 });
            //压缩方法
            message.Append(new byte[1] { 0 });
            message.Append(new byte[] { 0, 0 });
            ////todo:测试
            //message.RemoveFrame(message.Last);
            ////扩展长度
            //byte[] extension = "00 0a 00 16 00 14 00 17 00 18 00 19 00 09 00 0a 00 0b 00 0c 00 0d 00 0e 00 16 00 0b 00 02 01 00 00 0d 00 16 00 14 06 03 06 01 05 03 05 01 04 03 04 01 04 02 02 03 02 01 02 02 00 17 00 00 ff 01 00 01 00".ConvertHexToByteArray();
            //message.Append(extension.LengthToBytes(2));
            //message.Append(extension);
            InsertLength(message);
            message.Push(handShakeType);
            return message;
        }
    }
}