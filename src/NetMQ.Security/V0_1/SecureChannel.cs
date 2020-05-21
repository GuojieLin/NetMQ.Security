using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using JetBrains.Annotations;
using NetMQ.Security.Extensions;
using NetMQ.Security.V0_1.HandshakeMessages;

namespace NetMQ.Security.V0_1
{
    /// <summary>
    /// Class SecureChannel implements ISecureChannel and provides a secure communication channel between a client and a server.
    /// It provides for a X.509 certificate, and methods to process, encrypt, and decrypt messages.
    /// </summary>
    public class SecureChannel : ISecureChannel
    {
        internal HandshakeLayer m_handshakeLayer;
        internal RecordLayer RecordLayer;
        public Configuration Configuration { get; private set; }
        private readonly OutgoingMessageBag m_outgoingMessageBag;
        public byte[] SessionId { get; private set; }
        /// <summary>
        /// 当前使用的版本。
        /// </summary>
        public byte[] ProtocolVersion { get; private set; }

        private ConnectionEnd n_ConnectionEnd;

        /// <summary>
        /// Get whether a change-cipher-suite message has arrived.
        /// </summary>
        public bool ChangeSuiteChangeArrived { get; private set; }

        /// <summary>
        /// Get whether this SecureChannel is ready to exchange content messages.
        /// </summary>
        public bool SecureChannelReady { get; private set; }

        /// <summary>
        /// Get or set the X.509 digital certificate to be used for encryption of this channel.
        /// </summary>
        public X509Certificate2 Certificate
        {
            get { return m_handshakeLayer.LocalCertificate; }
            set { m_handshakeLayer.LocalCertificate = value; }
        }

        /// <summary>
        /// Get or set the collection of cipher-suites that are available. This maps to a simple byte-array.
        /// </summary>
        public CipherSuite[] AllowedCipherSuites
        {
            get { return m_handshakeLayer.AllowedCipherSuites; }
            set { m_handshakeLayer.AllowedCipherSuites = value; }
        }

        /// <summary>
        /// Create a new SecureChannel with the given <see cref="ConnectionEnd"/>.
        /// </summary>
        /// <param name="connectionEnd">the ConnectionEnd that this channel is to talk to</param>
        public static SecureChannel CreateClientSecureChannel(byte[] sesionId = null, Configuration configuration = null)
        {
            SecureChannel secureChannel = new SecureChannel(ConnectionEnd.Client, configuration);
            if (sesionId != null) secureChannel.UpdateSessionId(sesionId);
            return secureChannel;
        }
        /// <summary>
        /// Create a new SecureChannel with the given <see cref="ConnectionEnd"/>.
        /// </summary>
        /// <param name="connectionEnd">the ConnectionEnd that this channel is to talk to</param>
        public static SecureChannel CreateServerSecureChannel(Configuration configuration = null)
        {
            SecureChannel secureChannel = new SecureChannel(ConnectionEnd.Server, configuration);
            return secureChannel;
        }
        /// <summary>
        /// Create a new SecureChannel with the given <see cref="ConnectionEnd"/>.
        /// </summary>
        /// <param name="connectionEnd">the ConnectionEnd that this channel is to talk to</param>
        private SecureChannel(ConnectionEnd connectionEnd, Configuration configuration = null)
        {
            Configuration = configuration ?? new Configuration();
            n_ConnectionEnd = connectionEnd;

            m_handshakeLayer = new HandshakeLayer(this, connectionEnd);
            m_handshakeLayer.CipherSuiteChange += OnCipherSuiteChangeFromHandshakeLayer;
            RecordLayer = new RecordLayer();

            m_outgoingMessageBag = new OutgoingMessageBag(this);
            if (!Configuration.VerifyCertificate)
            {
                //若不验证证书，则直接返回true
                SetVerifyCertificate(c => true);
            }
        }
        /// <summary>
        /// 获取版本号
        /// </summary>
        /// <returns></returns>
        private byte[] GetVersion(bool standardTLSFormat)
        {
            return Constants.V3_3.ToArray();
        }
        /// <summary>
        /// 获取版本号
        /// </summary>
        /// <returns></returns>
        private byte[] GetSubVersion(bool standardTLSFormat)
        {
            return Constants.V3_3.ToArray();
        }
        /// <summary>
        /// Assign the delegate to use to verify the X.509 certificate.
        /// </summary>
        /// <param name="verifyCertificate"></param>
        public void SetVerifyCertificate(VerifyCertificateDelegate verifyCertificate)
        {
            m_handshakeLayer.VerifyCertificate = verifyCertificate;
        }

        /// <summary>
        /// Process handshake and change cipher suite messages. This method should be called for every incoming message until the method returns true.
        /// You cannot encrypt or decrypt messages until the method return true.
        /// Each call to the method may include outgoing messages that need to be sent to the other peer.
        /// </summary>
        /// <param name="incomingMessage">the incoming message from the other peer</param>
        /// <param name="outgoingMesssages">the list of outgoing messages that need to be sent to the other peer</param>
        /// <returns>true when the method completes the handshake stage and the SecureChannel is ready to encrypt and decrypt messages</returns>
        /// <exception cref="NetMQSecurityException">NetMQSecurityErrorCode.InvalidContentType: Unknown content type.</exception>
        /// <exception cref="NetMQSecurityException">NetMQSecurityErrorCode.InvalidFrameLength: Wrong length for protocol version frame.</exception>
        /// <exception cref="NetMQSecurityException">NetMQSecurityErrorCode.InvalidFrameLength: Wrong length for message size.</exception>
        /// <exception cref="NetMQSecurityException">NetMQSecurityErrorCode.InvalidProtocolVersion: Wrong protocol version.</exception>
        /// <remarks>
        /// Note: Within this library, this method is ONLY called from within the unit-tests.
        /// </remarks>
        public bool ProcessMessage(NetMQMessage incomingMessage, IList<NetMQMessage> outgoingMesssages)
        {
#if DEBUG
            if (incomingMessage != null)
            {
                Debug.WriteLine("[record layer(" + incomingMessage.Sum(f => f.BufferSize) + ")]");
            }
#endif
            ContentType contentType = ContentType.Handshake;

            if (incomingMessage != null)
            {
                // Verify that the first two frames are the protocol-version and the content-type,

                NetMQFrame contentTypeFrame = incomingMessage.Pop();

                if (contentTypeFrame.MessageSize != 1)
                {
                    throw new NetMQSecurityException(NetMQSecurityErrorCode.InvalidFrameLength, "wrong length for Content Type  size");
                }

                // Verify that the content-type is either handshake, or change-cipher-suit..
                contentType = (ContentType)contentTypeFrame.Buffer[0];

                if (contentType != ContentType.ChangeCipherSpec && contentType != ContentType.Handshake && contentType != ContentType.Alert)
                {
                    throw new NetMQSecurityException(NetMQSecurityErrorCode.InvalidContentType, "Unknown content type");
                }
                NetMQFrame protocolVersionFrame = incomingMessage.Pop();
                byte[] protocolVersionBytes = protocolVersionFrame.ToByteArray();

                if (protocolVersionBytes.Length != 2)
                {
                    throw new NetMQSecurityException(NetMQSecurityErrorCode.InvalidFrameLength, "Wrong length for protocol version frame");
                }
                if (n_ConnectionEnd == ConnectionEnd.Server && contentType == ContentType.Handshake)
                {
                    //第一次握手时
                    if (ProtocolVersion == null)
                    {
                        //校验记录层版本号是否支持
                        if (Constants.SupposeVersions.Any(p => p.SequenceEqual(protocolVersionBytes)))
                        {
                            //支持版本
                            ProtocolVersion = protocolVersionBytes;
                        }
                        else
                        {
                            throw new NetMQSecurityException(NetMQSecurityErrorCode.InvalidFrameLength, "the protocol version is not supposed");
                        }
                    }
                }
                //作为服务端首次接收到客户端
                if (!protocolVersionBytes.SequenceEqual(ProtocolVersion))
                {
                    throw new NetMQSecurityException(NetMQSecurityErrorCode.InvalidProtocolVersion, "Wrong protocol version");
                }
                RemoveLength(incomingMessage);
                if (ChangeSuiteChangeArrived)
                {
                    RecordLayer.SetSubProtocolVersion(m_handshakeLayer.SubProtocolVersion);

                    //已经收到ChangeCipherSuite，接下来就是Finish
                    //Finished报文是第一个解密报文。需要解密。
                    incomingMessage = RecordLayer.DecryptMessage(contentType, incomingMessage);
                }
                if (contentType == ContentType.Alert)
                {
                    throw new NetMQSecurityException(NetMQSecurityErrorCode.HandshakeException, "peer response alert[" + (AlertDescription)incomingMessage.Last.Buffer[0] + "]");
                }
            }
            else
            {
                //作为客户端确定使用的版本号,后续客户端和服务端通讯都要校验版本号一致性。
                //客户端使用3,3版本
                ProtocolVersion = GetVersion(Configuration.StandardTLSFormat);
            }

            bool result = false;
            if (contentType == ContentType.Handshake)
            {
                result = m_handshakeLayer.ProcessMessages(incomingMessage, m_outgoingMessageBag);
                this.SessionId = m_handshakeLayer.SessionID;
                if(m_outgoingMessageBag.Messages.Count() > 1)
                {
                    // Move the messages from the saved list over to the outgoing Messages collection..
                    foreach (NetMQMessage outgoingMesssage in m_outgoingMessageBag.Messages)
                    {
                        outgoingMesssages.Add(outgoingMesssage);
                    }
                }
                else
                {
                    // Move the messages from the saved list over to the outgoing Messages collection..
                    foreach (NetMQMessage outgoingMesssage in m_outgoingMessageBag.Messages)
                    {
                        outgoingMesssages.Add(outgoingMesssage);
                    }
                }
                m_outgoingMessageBag.Clear();
            }
            else
            {
                ////每个record计数都+1
                //RecordLayer.GetAndIncreaseReadSequneceNumber();
                //接下去的是Finished，需要加密。
                ChangeSuiteChangeArrived = true;
            }

            return (SecureChannelReady = result && ChangeSuiteChangeArrived);
        }

        private void RemoveLength(NetMQMessage incomingMessage)
        {
            if (Configuration.StandardTLSFormat)
            {
                //去除长度
                NetMQFrame lengthFrame = incomingMessage.Pop();
            }
        }

        private void OnCipherSuiteChangeFromHandshakeLayer(object sender, EventArgs e)
        {
            // The change cipher spec protocol exists to signal transitions in ciphering strategies.
            // The protocol consists of a single message, which is encrypted and compressed under the current(not the pending) connection state. 
            // The message consists of a single byte of value 1.
            // enum { change_cipher_spec(1), (255) } type;
            m_outgoingMessageBag.AddCipherChangeMessage(new byte[] { 1 });

            RecordLayer.SecurityParameters = m_handshakeLayer.SecurityParameters;

            RecordLayer.InitalizeCipherSuite();
            RecordLayer.SetSubProtocolVersion(m_handshakeLayer.SubProtocolVersion);
        }

        /// <param name="contentType">This identifies the type of content: ChangeCipherSpec, Handshake, or ApplicationData.</param>
        /// <param name="plainMessage">The unencrypted form of the message to be encrypted.</param>
        internal NetMQMessage InternalEncryptAndWrapMessage(ContentType contentType, NetMQMessage plainMessage)
        {
            byte[] bytes = new byte[plainMessage.Sum(m => m.BufferSize)];
            int offset = 0;
            foreach (var frame in plainMessage)
            {
                Buffer.BlockCopy(frame.Buffer, 0, bytes, offset, frame.BufferSize);
                offset += frame.BufferSize;
            }
            NetMQMessage encryptedMessage = new NetMQMessage();
            var encrpytFrameBytes = EncryptFrame(contentType, bytes);
            encryptedMessage.Append(encrpytFrameBytes);
            return encryptedMessage;
        }

        /// <summary>
        /// Encrypt the given NetMQMessage, wrapping it's content as application-data and prefixing it with the encryption protocol.
        /// </summary>
        /// <param name="plainMessage">The unencrypted form of the message to be encrypted.</param>
        /// <returns>a new NetMQMessage that is encrypted</returns>
        /// <exception cref="ArgumentNullException">plainMessage must not be null.</exception>
        /// <exception cref="NetMQSecurityException">NetMQSecurityErrorCode.SecureChannelNotReady: The secure channel must be ready.</exception>
        public NetMQMessage EncryptApplicationMessage([NotNull] NetMQMessage plainMessage)
        {
            if (!SecureChannelReady)
            {
                throw new NetMQSecurityException(NetMQSecurityErrorCode.SecureChannelNotReady, "Cannot encrypt messages until the secure channel is ready");
            }

            if (plainMessage == null)
            {
                throw new ArgumentNullException(nameof(plainMessage));
            }
            return InternalEncryptAndWrapMessage(ContentType.ApplicationData, plainMessage);
        }
        /// <summary>
        /// Encrypt the given NetMQMessage, wrapping it's content as application-data and prefixing it with the encryption protocol.
        /// </summary>
        /// <param name="plainMessage">The unencrypted form of the message to be encrypted.</param>
        /// <returns>a new NetMQMessage that is encrypted</returns>
        /// <exception cref="ArgumentNullException">plainMessage must not be null.</exception>
        /// <exception cref="NetMQSecurityException">NetMQSecurityErrorCode.SecureChannelNotReady: The secure channel must be ready.</exception>
        public byte[] EncryptApplicationBytes([NotNull] byte[] plainBytes)
        {
            if (!SecureChannelReady)
            {
                throw new NetMQSecurityException(NetMQSecurityErrorCode.SecureChannelNotReady, "Cannot encrypt messages until the secure channel is ready");
            }

            if (plainBytes == null)
            {
                throw new ArgumentNullException(nameof(plainBytes));
            }

            return EncryptFrame(ContentType.ApplicationData, plainBytes);
        }        /// <summary>
                 /// 包装成RecordLayer
                 /// </summary>
                 /// <param name="contentType">This identifies the type of content: ChangeCipherSpec, Handshake, or ApplicationData.</param>
                 /// <param name="plainMessage">The unencrypted form of the message to be encrypted.</param>
                 /// <returns></returns>
        internal byte[] WrapToRecordLayerMessage(ContentType contentType, byte[] bytes)
        {
            //将数据加密
            //Change Cipher Spec 步骤之前返回明文
            byte[] encryptedBytes = RecordLayer.EncryptMessage(contentType, bytes);
            byte[] recordLayerBytes = new byte[encryptedBytes.Length + 5];
            recordLayerBytes[0] = (byte)contentType;
            recordLayerBytes[1] = ProtocolVersion[0];
            recordLayerBytes[2] = ProtocolVersion[1];
            /// ContentType type;change_cipher_spec(20), alert(21), handshake(22), application_data(23), (255)
            /// ProtocolVersion version;33
            /// uint16 length;
            /// opaque fragment[TLSPlaintext.length];
            if (ProtocolVersion.SequenceEqual(Constants.V3_3))
            {
                //增加长度
                byte[] lengthBytes = encryptedBytes.LengthToBytes(2);
                Buffer.BlockCopy(lengthBytes, 0, recordLayerBytes, 3, lengthBytes.Length);
            }
            Buffer.BlockCopy(encryptedBytes, 0, recordLayerBytes, 5, encryptedBytes.Length);

            return recordLayerBytes;
        }

        public byte[] EncryptFrame(ContentType contentType, [NotNull] byte[] plainBytes)
        {
            //计算需要拆分包的个数
            int splitCount = 0;
            //每个ApplicationData包最大为2^14=16,384
            //超过的数据大小需要分片后(压缩)加密。
            splitCount = plainBytes.Length / Constants.MAX_TLS_PLAIN_TEXT_BYTE_SIZE;
            List<byte[]> encryptBytesList = new List<byte[]>(splitCount);
            int offset = 0;
            int count = 0;
            do
            {
                bool split = (plainBytes.Length - offset) > Constants.MAX_TLS_PLAIN_TEXT_BYTE_SIZE;
                int length = 0;
                if (split)
                {
                    length = Constants.MAX_TLS_PLAIN_TEXT_BYTE_SIZE;
                }
                else
                {
                    length = plainBytes.Length - offset;
                }
                byte[] splitPlainBytes = new byte[length];
                //超长分片
                Buffer.BlockCopy(plainBytes, offset, splitPlainBytes, 0, splitPlainBytes.Length);
                //每一层record都要添加seqnum
                byte[] encryptFrameBytes = WrapToRecordLayerMessage(contentType, splitPlainBytes);
                if (splitCount == 0) return encryptFrameBytes;
                encryptBytesList.Add(encryptFrameBytes);
                count++;
                offset += length;
            } while (offset < plainBytes.Length);
            //未分组，直接返回
            byte[] encryptBytes = new byte[encryptBytesList.Sum(b => b.Length)];
            offset = 0;
            foreach (var encryptMessage in encryptBytesList)
            {
                Buffer.BlockCopy(encryptMessage, 0, encryptBytes, offset, encryptMessage.Length);
                offset += encryptMessage.Length;
            }
            return encryptBytes;
        }

        /// <summary>
        /// Decrypt the given NetMQMessage, the first frame of which is assumed to contain the protocol version.
        /// </summary>
        /// <param name="cipherMessage">the NetMQMessage to decrypt</param>
        /// <returns>a NetMQMessage with the application-data decrypted</returns>
        /// <exception cref="ArgumentNullException">cipherMessage must not be null.</exception>
        /// <exception cref="NetMQSecurityException">NetMQSecurityErrorCode.SecureChannelNotReady: The secure channel must be ready.</exception>
        /// <exception cref="NetMQSecurityException">NetMQSecurityErrorCode.InvalidFramesCount: The cipher message must have at least 2 frames.</exception>
        /// <exception cref="NetMQSecurityException">NetMQSecurityErrorCode.InvalidProtocolVersion: The protocol must be the correct version.</exception>
        /// <exception cref="NetMQSecurityException">NetMQSecurityErrorCode.InvalidContentType: The message must contain application data.</exception>
        public NetMQMessage DecryptApplicationMessage([NotNull] NetMQMessage cipherMessage)
        {
            if (!SecureChannelReady)
            {
                throw new NetMQSecurityException(NetMQSecurityErrorCode.SecureChannelNotReady, "Cannot decrypt messages until the secure channel is ready");
            }

            if (cipherMessage == null)
            {
                throw new ArgumentNullException(nameof(cipherMessage));
            }

            if (cipherMessage.FrameCount < 2)
            {
                throw new NetMQSecurityException(NetMQSecurityErrorCode.InvalidFramesCount, "cipher message should have at least 2 frames");
            }

            NetMQFrame contentTypeFrame = cipherMessage.Pop();
            NetMQFrame protocolVersionFrame = cipherMessage.Pop();

            if (!protocolVersionFrame.ToByteArray().SequenceEqual(ProtocolVersion))
            {
                throw new NetMQSecurityException(NetMQSecurityErrorCode.InvalidProtocolVersion, "Wrong protocol version");
            }

            ContentType contentType = (ContentType)contentTypeFrame.Buffer[0];

            if (contentType != ContentType.ApplicationData && contentType != ContentType.Alert)
            {
                throw new NetMQSecurityException(NetMQSecurityErrorCode.InvalidContentType, "Not an alert message or application data message");
            }
            RemoveLength(cipherMessage);
            return RecordLayer.DecryptMessage(contentType, cipherMessage);
        }

        /// <summary>
        /// Decrypt the given NetMQMessage, the first frame of which is assumed to contain the protocol version.
        /// </summary>
        /// <param name="cipherMessage">the NetMQMessage to decrypt</param>
        /// <returns>a NetMQMessage with the application-data decrypted</returns>
        /// <exception cref="ArgumentNullException">cipherMessage must not be null.</exception>
        /// <exception cref="NetMQSecurityException">NetMQSecurityErrorCode.SecureChannelNotReady: The secure channel must be ready.</exception>
        /// <exception cref="NetMQSecurityException">NetMQSecurityErrorCode.InvalidFramesCount: The cipher message must have at least 2 frames.</exception>
        /// <exception cref="NetMQSecurityException">NetMQSecurityErrorCode.InvalidProtocolVersion: The protocol must be the correct version.</exception>
        /// <exception cref="NetMQSecurityException">NetMQSecurityErrorCode.InvalidContentType: The message must contain application data.</exception>
        public byte[] DecryptApplicationMessage([NotNull] byte[] cipherBytes)
        {
            if (!SecureChannelReady)
            {
                throw new NetMQSecurityException(NetMQSecurityErrorCode.SecureChannelNotReady, "Cannot decrypt messages until the secure channel is ready");
            }

            if (cipherBytes == null)
            {
                throw new ArgumentNullException(nameof(cipherBytes));
            }
            return RecordLayer.DecryptMessage(ContentType.ApplicationData, cipherBytes);
        }

        public void UpdateSessionId(byte[] sessionId)
        {
            SessionId = sessionId;
            m_handshakeLayer.UpdateSessionId(sessionId);
        }

        public NetMQMessage HandshakeFailure(AlertLevel alertLevel, byte[] protocolVersion = null)
        {
            if (protocolVersion == null) protocolVersion = new byte[2] { 3, 3 };
            NetMQMessage message = new NetMQMessage();
            message.Append(new[] { (byte)ContentType.Alert });
            message.Append(protocolVersion);
            message.Append(new byte[2] { 0, 2 });
            message.Append(new byte[1] { (byte)alertLevel });
            message.Append(new byte[1] { (byte)AlertDescription.HandshakeFailure });
            return message;
        }
        public NetMQMessage Alert(AlertLevel alertLevel, AlertDescription alertDescription)
        {
            NetMQMessage message = new NetMQMessage();
            message.Append(new[] { (byte)ContentType.Alert });
            message.Append(ProtocolVersion.ToArray());
            if (ProtocolVersion.SequenceEqual(Constants.V3_3))
            {
                message.Append(new byte[2] { 0, 2 });
            }
            message.Append(new byte[1] { (byte)alertLevel });
            message.Append(new byte[1] { (byte)alertDescription });
            return message;
        }
        /// <summary>
        /// Release any contained resources of this SecureChannel object.
        /// </summary>
        /// <remarks>
        /// This disposes of the handshake-layer and the record-layer.
        /// </remarks>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Release any contained resources of this SecureChannel object.
        /// </summary>
        /// <param name="disposing">set this to true if disposing of managed resources</param>
        /// <remarks>
        /// This disposes of the handshake-layer and the record-layer.
        /// </remarks>
        protected virtual void Dispose(bool disposing)
        {
            if (!disposing)
                return;

            if (m_handshakeLayer != null)
            {
                m_handshakeLayer.Dispose();
                m_handshakeLayer = null;
            }

            if (RecordLayer != null)
            {
                RecordLayer.Dispose();
                RecordLayer = null;
            }
        }

        public byte[] DecryptApplicationBytes(byte[] cipherMessage)
        {
            throw new NotImplementedException();
        }

        #region 解析RecordLayer
        public bool ResolveRecordLayer(byte[] bytes, out int offset, out List<NetMQMessage> sslMessages)
        {
            sslMessages = new List<NetMQMessage>();
            offset = 0;
            bool changeSuiteChangeArrived = this.ChangeSuiteChangeArrived;
            do
            {
                List<NetMQMessage> sslMessage;
                if (bytes.GetRecordLayerNetMQMessage(ref changeSuiteChangeArrived, ref offset, out sslMessage))
                {
                    sslMessages.AddRange(sslMessage);
                }
                else
                {
                    break;
                }
            } while (offset < bytes.Length);
            return sslMessages.Count > 0;
        }

        #endregion
    }
}
