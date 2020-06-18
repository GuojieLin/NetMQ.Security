using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using JetBrains.Annotations;
using NetMQ.Security.Decoder;
using NetMQ.Security.Enums;
using NetMQ.Security.Extensions;
using NetMQ.Security.Layer;
using NetMQ.Security.TLS12.HandshakeMessages;
using NetMQ.Security.TLS12.Layer;

namespace NetMQ.Security.TLS12
{
    /// <summary>
    /// Class SecureChannel implements ISecureChannel and provides a secure communication channel between a client and a server.
    /// It provides for a X.509 certificate, and methods to process, encrypt, and decrypt messages.
    /// </summary>
    public class SecureChannel : ISecureChannel
    {
        internal HandshakeLayer m_handshakeLayer;
        internal Context Context;
        public Configuration Configuration { get; private set; }
        public byte[] SessionId { get; private set; }
        /// <summary>
        /// 当前使用的版本。
        /// </summary>
        public ProtocolVersion ProtocolVersion { get; private set; }

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
        public RecordLayer CreateRecordLayer()
        {
            RecordLayer recordLayer = new RecordLayer();
            recordLayer.ProtocolVersion = ProtocolVersion;
            return recordLayer;
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
            Context = new Context();

            if (!Configuration.VerifyCertificate)
            {
                //若不验证证书，则直接返回true
                SetVerifyCertificate(c => true);
            }
            //默认不支持的协议号，需要双方协商
            ProtocolVersion = ProtocolVersion.UN_SUPPOSE_VERSION;
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
        /// Assign the delegate to use to verify the X.509 certificate.
        /// </summary>
        /// <param name="verifyCertificate"></param>
        public void SetProtocolVersion(ProtocolVersion protocolVersion)
        {
            ProtocolVersion = protocolVersion;
        }

        /// <summary>
        /// 将解析完成的RecordLayer进行处理，需要注意，这里只处理握手请求。
        /// 握手完毕后数据加密和解密不应该在调用该方法。
        /// </summary>
        /// <param name="incomingRecordLayer"></param>
        /// <param name="outRecordLayers"></param>
        /// <returns></returns>
        public bool ProcessMessage(RecordLayer incomingRecordLayer, List<RecordLayer> outRecordLayers)
        {
            ContentType contentType = ContentType.Handshake;
            bool result = false;
            if (incomingRecordLayer != null)
            {
                // Verify that the content-type is either handshake, or change-cipher-suit..
                contentType = incomingRecordLayer.ContentType;

                if (contentType != ContentType.ChangeCipherSpec && contentType != ContentType.Handshake && contentType != ContentType.Alert)
                {
                    throw new NetMQSecurityException(NetMQSecurityErrorCode.InvalidContentType, "Unknown content type");
                }
                //加密
                if (ChangeSuiteChangeArrived)
                {
                    //只有Finished和Alert报文可以到这里
                    //一定是加密的
                    if (!incomingRecordLayer.RecordProtocols[0].IsEncrypted)
                    {
                        throw new NetMQSecurityException(NetMQSecurityErrorCode.HandshakeUnexpectedMessage, "Unexpected Message");
                    }
                    //已经收到ChangeCipherSuite，接下来就是Finish
                    //Finished报文是第一个解密报文。需要解密。
                    var decryptedDate = Context.DecryptMessage(contentType, incomingRecordLayer.RecordProtocols[0].HandShakeData);
                    //解析解密后的数据
                    var decryptProtocol = DecoderFactory.Decode(contentType, (ReadonlyBuffer<byte>)decryptedDate, false/*数据已解密*/);
                    //替换为解密后的协议
                    incomingRecordLayer.RecordProtocols = decryptProtocol;
                    //替换加密协议
                }
                if (contentType == ContentType.Alert)
                {
                    ProcessAlert(incomingRecordLayer.RecordProtocols[0]);
                    incomingRecordLayer.ProtocolVersion = this.ProtocolVersion;
                    //warn不关闭连接,但是要给外部处理
                    outRecordLayers.Add(incomingRecordLayer);
                }
            }
            else
            {
                //作为客户端确定使用的版本号,后续客户端和服务端通讯都要校验版本号一致性。
                //客户端使用3,3版本
                ProtocolVersion = Configuration.SupposeProtocolVersions[0];
                //客户端握手
                result = m_handshakeLayer.ProcessMessages(null, outRecordLayers);

                return false;
            }

            if (contentType == ContentType.Handshake)
            {
                //握手时可能会有多个handshake协议负载到一个recordlayer上。
                foreach (var recordProtocol in incomingRecordLayer.RecordProtocols)
                {
                    result = m_handshakeLayer.ProcessMessages((HandshakeProtocol)recordProtocol, outRecordLayers);
                    this.SessionId = m_handshakeLayer.SessionID;
                }
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

        private void ProcessAlert(RecordProtocol recordProtocol)
        {
            AlertProtocol alertProtocol = recordProtocol as AlertProtocol;
            if (alertProtocol.Level == AlertLevel.Fatal)
            {
                //具有致命级别的警报消息会导致立即终止连接。
                throw new NetMQSecurityException(NetMQSecurityErrorCode.HandshakeException, "peer response alert[" + alertProtocol.Description + "]");
            }
            else
            {
                //非致命记录一下，暂时不处理
#if DEBUG
                Debug.WriteLine("[warn alert[" + alertProtocol.Description + "]");
#endif
            }

        }

        /// <summary>
        /// 当接收到CipherSuiteChange时，更新安全参数
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void OnCipherSuiteChangeFromHandshakeLayer(object sender, EventArgs e)
        {

            Context.SecurityParameters = m_handshakeLayer.SecurityParameters;

            Context.InitalizeCipherSuite();
            Context.SetProtocolVersion(ProtocolVersion);
        }

        /// <summary>
        /// Encrypt the given NetMQMessage, wrapping it's content as application-data and prefixing it with the encryption protocol.
        /// </summary>
        /// <param name="plainMessage">The unencrypted form of the message to be encrypted.</param>
        /// <returns>a new NetMQMessage that is encrypted</returns>
        /// <exception cref="ArgumentNullException">plainMessage must not be null.</exception>
        /// <exception cref="NetMQSecurityException">NetMQSecurityErrorCode.SecureChannelNotReady: The secure channel must be ready.</exception>
        public byte[] EncryptAlert([NotNull] AlertProtocol alert)
        {
            if (!SecureChannelReady)
            {
                throw new NetMQSecurityException(NetMQSecurityErrorCode.SecureChannelNotReady, "Cannot encrypt messages until the secure channel is ready");
            }

            if (alert == null)
            {
                throw new ArgumentNullException(nameof(alert));
            }

            return InternalEncryptAndWrapAlertMessage(ContentType.Alert, new ReadonlyBuffer<byte>(alert));
        }
        /// <summary>
        /// Encrypt the given NetMQMessage, wrapping it's content as application-data and prefixing it with the encryption protocol.
        /// </summary>
        /// <param name="plainMessage">The unencrypted form of the message to be encrypted.</param>
        /// <returns>a new NetMQMessage that is encrypted</returns>
        /// <exception cref="ArgumentNullException">plainMessage must not be null.</exception>
        /// <exception cref="NetMQSecurityException">NetMQSecurityErrorCode.SecureChannelNotReady: The secure channel must be ready.</exception>
        public byte[] EncryptApplicationData([NotNull] ReadonlyBuffer<byte> buffer)
        {
            if (!SecureChannelReady)
            {
                throw new NetMQSecurityException(NetMQSecurityErrorCode.SecureChannelNotReady, "Cannot encrypt messages until the secure channel is ready");
            }

            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }

            return ToBytes(InternalEncryptAndWrapApplicationData(ContentType.ApplicationData, buffer));
        }
        public static byte[] ToBytes(List<RecordLayer> message)
        {
            if (message.Count == 1) return message.First();
            //TODO多个需要优化性能。
            byte[] data = new byte[message.Sum(f => ((byte[])f).Length)];
            int offset = 0;
            foreach (var frame in message)
            {
                byte[] d = frame;
                Buffer.BlockCopy(d, 0, data, offset, d.Length);
                offset += d.Length;
            }
            return data;
        }
        /// <summary>
        /// 包装成RecordLayer
        /// </summary>
        /// <param name="contentType">This identifies the type of content: ChangeCipherSpec, Handshake, or ApplicationData.</param>
        /// <param name="plainMessage">The unencrypted form of the message to be encrypted.</param>
        /// <returns></returns>
        internal byte[] WrapToRecordLayerMessage(ContentType contentType, byte[] bytes)
        {
            //将数据加密
            //Change Cipher Spec 步骤之前返回明文
            byte[] encryptedBytes = Context.EncryptMessage(contentType, bytes);
            byte[] recordLayerBytes = new byte[encryptedBytes.Length + 5];
            recordLayerBytes[0] = (byte)contentType;
            recordLayerBytes[1] = ProtocolVersion.Major;
            recordLayerBytes[2] = ProtocolVersion.Minor;
            /// ContentType type;change_cipher_spec(20), alert(21), handshake(22), application_data(23), (255)
            /// ProtocolVersion version;33
            /// uint16 length;
            /// opaque fragment[TLSPlaintext.length];
            /// 
            //增加长度
            byte[] lengthBytes = encryptedBytes.LengthToBigEndianBytes(2);
            Buffer.BlockCopy(lengthBytes, 0, recordLayerBytes, 3, lengthBytes.Length);

            Buffer.BlockCopy(encryptedBytes, 0, recordLayerBytes, 5, encryptedBytes.Length);

            return recordLayerBytes;
        }
        internal byte[] WrapToRecordLayerMessage(ContentType contentType, ReadonlyBuffer<byte> bytes)
        {
            //将数据加密
            //Change Cipher Spec 步骤之前返回明文
            byte[] encryptedBytes = Context.EncryptMessage(contentType, bytes);
            byte[] recordLayerBytes = new byte[encryptedBytes.Length + 5];
            recordLayerBytes[0] = (byte)contentType;
            recordLayerBytes[1] = ProtocolVersion.Major;
            recordLayerBytes[2] = ProtocolVersion.Minor;
            /// ContentType type;change_cipher_spec(20), alert(21), handshake(22), application_data(23), (255)
            /// ProtocolVersion version;33
            /// uint16 length;
            /// opaque fragment[TLSPlaintext.length];
            /// 
            //增加长度
            byte[] lengthBytes = encryptedBytes.LengthToBigEndianBytes(2);
            Buffer.BlockCopy(lengthBytes, 0, recordLayerBytes, 3, lengthBytes.Length);

            Buffer.BlockCopy(encryptedBytes, 0, recordLayerBytes, 5, encryptedBytes.Length);

            return recordLayerBytes;
        }

        internal RecordLayer InternalEncryptAndWrapAlertMessage(ContentType contentType, [NotNull] ReadonlyBuffer<byte> buffer)
        {
            byte[] encryptFrameBytes = Context.EncryptMessage(contentType, buffer);
            AlertProtocol applicationDataProtocol = new AlertProtocol(true);
            applicationDataProtocol.HandShakeData = new ReadonlyBuffer<byte>(encryptFrameBytes);
            RecordLayer recordLayer = this.CreateRecordLayer();
            recordLayer.AddAlertProtocol(applicationDataProtocol);
            return recordLayer;
        }
        internal List<RecordLayer> InternalEncryptAndWrapApplicationData(ContentType contentType, [NotNull] ReadonlyBuffer<byte> buffer)
        {
            List<RecordLayer> recordLayers = new List<RecordLayer>();
            //计算需要拆分包的个数
            int splitCount = 0;
            //每个ApplicationData包最大为2^14=16,384
            //超过的数据大小需要分片后(压缩)加密。
            splitCount = buffer.Length / Constants.MAX_TLS_PLAIN_TEXT_BYTE_SIZE;
            do
            {
                bool split = buffer.Length > Constants.MAX_TLS_PLAIN_TEXT_BYTE_SIZE;
                int length = 0;
                ReadonlyBuffer<byte> splitPlainBytes;
                if (split)
                {
                    length = Constants.MAX_TLS_PLAIN_TEXT_BYTE_SIZE;
                    splitPlainBytes = buffer.Slice(0, length);
                }
                else
                {
                    length = buffer.Length;
                    splitPlainBytes = buffer;
                }
                //每一层record都要添加seqnum
                byte[] encryptFrameBytes = Context.EncryptMessage(contentType, splitPlainBytes);
                ApplicationDataProtocol applicationDataProtocol = new ApplicationDataProtocol();
                applicationDataProtocol.HandShakeData = new ReadonlyBuffer<byte>(encryptFrameBytes);
                RecordLayer recordLayer = this.CreateRecordLayer();
                recordLayer.AddApplicationDataProtocol(applicationDataProtocol);
                recordLayers.Add(recordLayer);
                buffer.Position(length);
            } while (buffer.Length > 0);
            return recordLayers;
        }
        public void UpdateSessionId(byte[] sessionId)
        {
            SessionId = sessionId;
            m_handshakeLayer.UpdateSessionId(sessionId);
        }

        public RecordLayer CreateAlert(AlertLevel alertLevel, AlertDescription alertDescription)
        {
            AlertProtocol alertProtocol = new AlertProtocol();
            alertProtocol.Level = alertLevel;
            alertProtocol.Description = alertDescription;
            RecordLayer recordLayer = CreateRecordLayer();
            recordLayer.AddAlertProtocol(alertProtocol);
            return recordLayer;
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

            if (Context != null)
            {
                Context.Dispose();
                Context = null;
            }
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
        /// <summary>
        /// 解密数据
        /// </summary>
        /// <param name="cipherBytes"></param>
        /// <returns></returns>
        public byte[] DecryptApplicationData([NotNull] ReadonlyBuffer<byte> cipherBytes)
        {
            if (!SecureChannelReady)
            {
                throw new NetMQSecurityException(NetMQSecurityErrorCode.SecureChannelNotReady, "Cannot decrypt messages until the secure channel is ready");
            }

            if (cipherBytes == null)
            {
                throw new ArgumentNullException(nameof(cipherBytes));
            }
            return Context.DecryptMessage(ContentType.ApplicationData, cipherBytes);
        }
        #region 解析RecordLayer
        /// <summary>
        /// 将数据解析成recordLayer
        /// 当握手已完成，则接收到会解析Finished，Alert
        /// 握手已完成不应该再调用该方法。
        /// 当握手完成，会解析出一个或多个握手的RecordLayer。
        /// </summary>
        /// <param name="buffer">接收到的内容</param>
        /// <param name="offset">解析出的RecordLayer数据</param>
        /// <param name="recordLayers"></param>
        /// <param name="responseRecordLayer">layer是否需要进行响应。若进行响应，则直接响应给对端，否则需要对解析出的record
        /// 进行处理</param>
        /// <returns>握手是否完成</returns>
        public bool ResolveRecordLayer(ReadonlyBuffer<byte> buffer, List<RecordLayer> recordLayers, List<RecordLayer> outHandshakeLayers)
        {
            if (SecureChannelReady)
            {
                ResolveEncrpyedRecordLayer(buffer, recordLayers);
                return true;
            }
            else
            {
                bool result = ResolveHandshakeLayer(buffer, outHandshakeLayers);
                return result;
            }
        }

        /// <summary>
        /// 解析握手数据并处理握手
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="outHandshakeLayers">响应给对端的握手数据</param>
        /// <returns></returns>
        private bool ResolveHandshakeLayer(ReadonlyBuffer<byte> buffer, List<RecordLayer> outHandshakeLayers)
        {
            bool result = false;
            do
            {
                int offset = 0;
                RecordLayer recordLayer;
                if (DecoderFactory.Decode(buffer, this.ChangeSuiteChangeArrived, out offset, out recordLayer))
                {
                    //解析成功 
                    if (recordLayer != null)
                    {
                        //握手数据需要直接处理，
                        //因为后一层需要前一层的状态才能处理。
                        result = ProcessMessage(recordLayer, outHandshakeLayers);
                    }
                }
                else
                {
                    break;
                }
                buffer.Position(offset);
                //若result为true，表示握手结束,不再解析后面的数据，若服务端。
                if (result) return result;
            } while (buffer.Length > 0);
            return false;
        }

        /// <summary>
        /// 解析加密数据，但是并没有解密。仅根据协议长度解析出RecordLayer，协议为Alert Protocol或Application Data Protocol
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="recordLayers"></param>
        private void ResolveEncrpyedRecordLayer(ReadonlyBuffer<byte> buffer, List<RecordLayer> recordLayers)
        {
            //Encrpyed Alert
            //Encrpyed Application Data
            do
            {
                int offset = 0;
                List<RecordLayer> temp = new List<RecordLayer>();
                RecordLayer recordLayer;
                if (DecoderFactory.Decode(buffer, this.ChangeSuiteChangeArrived, out offset, out recordLayer))
                {
                    //解析成功 处理
                    if (recordLayer != null) recordLayers.Add(recordLayer);
                }
                else
                {
                    break;
                }
                buffer.Position(offset);
            } while (buffer.Length > 0);
        }


        #endregion
    }
}
