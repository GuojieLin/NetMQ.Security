using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using NetMQ.Security.Enums;
using NetMQ.Security.Extensions;
using NetMQ.Security.Layer;
using NetMQ.Security.TLS12.HandshakeMessages;
using NetMQ.Security.TLS12.Layer;

namespace NetMQ.Security.TLS12
{
    internal class HandshakeLayer : IDisposable
    {
        /// <summary>
        /// This is the SecureChannel that this handshake-protocol is communicating over.
        /// </summary>
        private readonly SecureChannel m_secureChannel;

        /// <summary>
        /// This denotes the length of the byte-array that holds the random-number value.
        /// </summary>
        public const int RandomNumberLength = 32;

        /// <summary>
        /// SessionID长度
        /// </summary>
        public const int SessionIdLength = 0;
        /// <summary>
        /// This denotes the length of the byte-array that holds the master-secret.
        /// </summary>
        public const int MasterSecretLength = 48;

        /// <summary>
        /// This is simply a string literal containing "master secret".
        /// </summary>
        public string MasterSecretLabel = "master secret";

        /// <summary>
        /// This is simply a string literal containing "client finished".
        /// </summary>
        public string ClientFinshedLabel = "client finished";

        /// <summary>
        /// This is simply a string literal containing "server finished".
        /// </summary>
        public string ServerFinishedLabel = "server finished";

        /// <summary>
        /// This serves to remember which HandshakeType was last received.
        /// </summary>
        internal HandshakeType m_lastReceivedMessage = HandshakeType.HelloRequest;

        /// <summary>
        /// This serves to remember which HandshakeType was last sent.
        /// </summary>
        internal HandshakeType m_lastSentMessage = HandshakeType.HelloRequest;

        /// <summary>
        /// This is the local hash-calculator, as opposed to the hash-calculator for the remote-peer.
        /// It uses the SHA-256 algorithm (SHA stands for Standard Hashing Algorithm).
        /// </summary>
        private SHA256 m_localHash;

        /// <summary>
        /// This is the hash-calculator for the remote peer.
        /// It uses the SHA-256 algorithm (SHA stands for Standard Hashing Algorithm).
        /// </summary>
        private SHA256 m_remoteHash;

        /// <summary>
        /// This is the random-number-generator that is used to create cryptographically-strong random byte-array data.
        /// </summary>
        private RandomNumberGenerator m_rng = new RNGCryptoServiceProvider();

        /// <summary>
        /// This flag indicates when the handshake has finished. It is set true in method OnFinished.
        /// </summary>
        private bool m_done;

        /// <summary>
        /// This is the Pseudo-Random number generating-Function (PRF) that is being used.
        /// It is initialized to a SHA256PRF.
        /// </summary>
        private IPRF m_prf = new SHA256PRF();


        public byte[] SessionID { get; private set; }
        /// <summary>
        /// Create a new HandshakeLayer object given a SecureChannel and which end of the connection it is to be.
        /// </summary>
        /// <param name="secureChannel">the SecureChannel that comprises the secure functionality of this layer</param>
        /// <param name="connectionEnd">this specifies which end of the connection - Server or Client</param>
        public HandshakeLayer(SecureChannel secureChannel, ConnectionEnd connectionEnd)
        {
            // SHA256 is a class that computes the SHA-256 (SHA stands for Standard Hashing Algorithm) of it's input.
            m_localHash = SHA256.Create();
            m_remoteHash = SHA256.Create();

            m_secureChannel = secureChannel;
            SecurityParameters = new SecurityParameters
            {
                Entity = connectionEnd,
                CompressionAlgorithm = CompressionMethod.Null,
                PRFAlgorithm = PRFAlgorithm.SHA256,
                CipherType = CipherType.Block
            };
            AllowedCipherSuites = new[]
            {
                CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
                CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA
            };

            VerifyCertificate = c => c.Verify();
        }

        public SecurityParameters SecurityParameters { get; }

        /// <summary>
        /// Get or set the array of allowed cipher-suites.
        /// </summary>
        public CipherSuite[] AllowedCipherSuites { get; set; }

        /// <summary>
        /// Get or set the local X.509-certificate.
        /// </summary>
        public X509Certificate2 LocalCertificate { get; set; }

        /// <summary>
        /// Get or set the remote X.509-certificate.
        /// </summary>
        public X509Certificate2 RemoteCertificate { get; set; }

        /// <summary>
        /// Get the Pseudo-Random number generating-Function (PRF) that is being used.
        /// </summary>
        public IPRF PRF => m_prf;

        /// <summary>
        /// This event signals a change to the cipher-suite.
        /// </summary>
        public event EventHandler CipherSuiteChange;

        /// <summary>
        /// Get or set the delegate to use to call the method for verifying the certificate.
        /// </summary>
        public VerifyCertificateDelegate VerifyCertificate { get; set; }

        /// <summary>
        /// Given an incoming handshake-protocol message, route it to the corresponding handler.
        /// </summary>
        /// <param name="incomingMessage">the NetMQMessage that has come in</param>
        /// <param name="outgoingMessages">a collection of NetMQMessages that are to be sent</param>
        /// <returns>true if finished - ie, an incoming message of type Finished was received</returns>
        /// <exception cref="ArgumentNullException"><paramref name="incomingMessage"/> must not be <c>null</c>.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="incomingMessage"/> must have a valid <see cref="HandshakeType"/>.</exception>
        public bool ProcessMessages(HandshakeProtocol protocol , IList<RecordLayer> outRecordLayers)
        {
            if (protocol == null)
            {
                if (m_lastReceivedMessage == m_lastSentMessage &&
                    m_lastSentMessage == HandshakeType.HelloRequest &&
                    SecurityParameters.Entity == ConnectionEnd.Client)
                {
                    RecordLayer recordLayer = new RecordLayer();
                    //客户端发送握手
                    OnHelloRequest(recordLayer);
                    outRecordLayers.Add(recordLayer);
                    return false;
                }
                else
                {
                    throw new ArgumentNullException(nameof(protocol));
                }
            }
            HandshakeType handshakeType = protocol.HandshakeType;

            switch (handshakeType)
            {
                case HandshakeType.HelloRequest:
                    {
                        /// 当客户端收到了服务端的Hello Request时可以有以下4种行为。
                        /// 1. 当客户端正在协商会话，可以忽略该消息。
                        /// 2. 若客户端未在协商会话但不希望重新协商时，可以忽略该消息。
                        /// 3. 若客户端未在协商会话但不希望重新协商时，可以发送no_renegotiation警报。
                        /// 4. 若客户端希望重新协商会话，则需要发送ClientHello重新进行TLS握手。
                        ////接收到对端的HelloRequest重新协商。暂时抛出异常重置连接
                        //NetMQMessage alert = m_secureChannel.HandshakeFailure(AlertLevel.Fatal, m_secureChannel.ProtocolVersion);
                        ////抛出异常，返回alert协议，通知客户端断开连接。
                        //throw new AlertException(alert, new Exception(AlertDescription.NoRenegotiation.ToString()));
                        //这里简单处理，直接忽略消息
                        break;
                    }
                case HandshakeType.ClientHello:
                    {
                        RecordLayer recordLayer = m_secureChannel.CreateRecordLayer();
                        OnClientHello(protocol, recordLayer);
                        outRecordLayers.Add(recordLayer);
                        break;
                    }
                case HandshakeType.ServerHello:
                    OnServerHello(protocol);
                    break;
                case HandshakeType.Certificate:
                    OnCertificate(protocol);
                    break;
                case HandshakeType.ServerHelloDone:
                    OnServerHelloDone(protocol, outRecordLayers);
                    break;
                case HandshakeType.ClientKeyExchange:
                    OnClientKeyExchange(protocol, outRecordLayers);
                    break;
                case HandshakeType.Finished:
                    {
                        RecordLayer recordLayer = OnFinished(protocol);
                        if (recordLayer != null)
                        {
                            outRecordLayers.Add(recordLayer);
                        }
                        break;
                    }
                default:
                    {
                        AlertProtocol alert = new AlertProtocol(this.m_secureChannel.ChangeSuiteChangeArrived);
                        alert.Level = AlertLevel.Fatal;
                        alert.Description = AlertDescription.UnexpectedMessage;
                        //抛出异常，返回alert协议，通知客户端断开连接。
                        throw new AlertException(alert, new Exception(AlertDescription.UnexpectedMessage.ToString()));
                    }
            }

            m_lastReceivedMessage = handshakeType;

            return m_done;
        }
        /// <summary>
        /// Compute the hash of the given message twice, first using the local hashing algorithm
        /// and then again using the remote-peer hashing algorithm.
        /// handshake_messages
        /// All of the data from all messages in this handshake (not
        ///   including any HelloRequest messages) up to, but not including,
        ///    this message.This is only data visible at the handshake layer
        /// and does not include record layer headers.This is the
        /// concatenation of all the Handshake structures as defined in
        /// Section 7.4, exchanged thus far.
        /// </summary>
        /// <param name="message">the NetMQMessage whose frames are to be hashed</param>
        private void HashLocalAndRemote(byte[] data)
        {
            HashLocal(data);
            HashRemote(data);
        }

        /// <summary>
        /// Use the local (as opposed to that of the remote-peer) hashing algorithm to compute a hash
        /// of the frames within the given NetMQMessage.
        /// </summary>
        /// <param name="message">the NetMQMessage whose frames are to be hashed</param>
        private void HashLocal(byte[] message)
        {
#if DEBUG
            Debug.WriteLine("[write] MD5 and SHA1 hashes:  " + BitConverter.ToString(message));
#endif
            Hash(m_localHash, message);
        }

        /// <summary>
        /// Use the remote-peer hashing algorithm to compute a hash
        /// of the frames within the given NetMQMessage.
        /// </summary>
        /// <param name="message">the NetMQMessage whose frames are to be hashed</param>
        private void HashRemote(byte[] message)
        {
#if DEBUG
            Debug.WriteLine("[read] MD5 and SHA1 hashes:  " + BitConverter.ToString(message));
#endif
            Hash(m_remoteHash, message);
        }
        /// <summary>
        /// Compute a hash of the bytes of the buffer within the frames of the given NetMQMessage.
        /// </summary>
        /// <param name="hash">the hashing-algorithm to employ</param>
        /// <param name="message">the NetMQMessage whose frames are to be hashed</param>
        private void Hash(HashAlgorithm hash, byte[] message)
        {
            // Access the byte-array that is the frame's buffer.
            byte[] bytes = message.ToArray();
            // Compute the hash value for the region of the input byte-array (bytes), starting at index 0,
            // and copy the resulting hash value back into the same byte-array.
            hash.TransformBlock(bytes, 0, bytes.Length, bytes, 0);
        }
        private void OnHelloRequest(RecordLayer outgoingMessages)
        {
            HandshakeProtocol protocol = new HandshakeProtocol();
            //客户端根据配置决定握手层版本号
            var clientHelloMessage = new ClientHelloMessage();
            outgoingMessages.ProtocolVersion = clientHelloMessage.Version = ProtocolVersion.TLS12;
            clientHelloMessage.Random = new byte[RandomNumberLength];

            clientHelloMessage.SessionID = SessionID ?? EmptyArray<byte>.Instance;

            m_rng.GetBytes(clientHelloMessage.Random);

            SecurityParameters.ClientRandom = clientHelloMessage.Random;

            clientHelloMessage.CipherSuites = AllowedCipherSuites;
            protocol.SetHandshakeMessage(clientHelloMessage);
            byte[] outgoingMessage = protocol.HandShakeData;

            HashLocalAndRemote(outgoingMessage);
            //第一个record的seqnum从0开始
            outgoingMessages.AddHandshake(protocol);
            m_lastSentMessage = HandshakeType.ClientHello;
        }

        /// <exception cref="NetMQSecurityException">The client hello message must not be received while expecting a different message.</exception>
        private void OnClientHello(HandshakeProtocol protocol, RecordLayer outRecordLayer)
        {
            ClientHelloMessage message = protocol.HandshakeMessage as ClientHelloMessage;
            Debug.Assert(message != null);
            //服务端收到ClientHello，
            //1. 客户端主动TLS握手，服务端为默认状态
            //2. 服务端发起HelloRequesst 要求重新握手。
            if (m_lastReceivedMessage != HandshakeType.HelloRequest || m_lastSentMessage != HandshakeType.HelloRequest)
            {
                throw new NetMQSecurityException(NetMQSecurityErrorCode.HandshakeUnexpectedMessage, "Client Hello received when expecting another message");
            }

            HashLocalAndRemote(protocol.HandShakeData);
            //协商版本号
            NegotiateVersioin(message.Version);
            outRecordLayer.ProtocolVersion = m_secureChannel.ProtocolVersion;
            //获取保存子协议版本
            //获取到客户端的sessionid
            this.SessionID = message.SessionID;
            SecurityParameters.ClientRandom = message.Random;

#if DEBUG
            Debug.WriteLine("Session ID:  " + BitConverter.ToString(message.Random));
            Debug.WriteLine("RandomCookie:  " + BitConverter.ToString(this.SessionID));
#endif
            AddServerHelloMessage(outRecordLayer, message.CipherSuites);

            AddCertificateMessage(outRecordLayer);

            AddServerHelloDone(outRecordLayer);
        }

        internal void NegotiateVersioin(ProtocolVersion currentVersion)
        {
            ProtocolVersion maxSupposeVersionl = ProtocolVersion.UN_SUPPOSE_VERSION;
            foreach(var version in m_secureChannel.Configuration.SupposeProtocolVersions)
            {
                // 服务端根据客户端发送的版本号返回一个服务端支持的最高版本号。若客户端不支持服务器选择的版本号，则客户端必须发送`protocol_version`警报消息并关闭连接。
                // 若服务端接收到的版本号小于当前支持的最高版本，且服务端希望与旧客户端协商，则返回不大于客户端版本的服务端最高版本。若服务端仅支持大于client_version的版本，则必须发送`protocol_version`警报消息并关闭连接。
                // 如果服务器收到的版本号大于服务器支持的最高版本的版本，则必须返回服务器所支持的最高版本。
            
                if (version == currentVersion)
                {
                    m_secureChannel.SetProtocolVersion(version);
                    return;
                }
                if(maxSupposeVersionl == ProtocolVersion.UN_SUPPOSE_VERSION && version< currentVersion)
                {
                    maxSupposeVersionl = version;
                }
            }
            if(maxSupposeVersionl == ProtocolVersion.UN_SUPPOSE_VERSION)
            {
                throw new NetMQSecurityException(NetMQSecurityErrorCode.InvalidProtocolVersion, "the hand shake protocol version is not supposed");
                //NetMQMessage alert = m_secureChannel.Alert(AlertLevel.Fatal, AlertDescription.ProtocolVersion);
                //throw new AlertException(alert, null);
            }
#if DEBUG
            Debug.WriteLine("Choose Highest Client Suppose Version: " + BitConverter.ToString(maxSupposeVersionl));
#endif
            //选择一个最高支持的版本
            m_secureChannel.SetProtocolVersion(maxSupposeVersionl);
        }
        private void AddServerHelloDone(RecordLayer outgoingMessages)
        {
            HandshakeProtocol protocol = new HandshakeProtocol();
            var serverHelloDoneMessage = new ServerHelloDoneMessage();
            protocol.SetHandshakeMessage(serverHelloDoneMessage);
            outgoingMessages.AddHandshake(protocol);
            byte[] outgoingMessage = protocol.HandShakeData;
            HashLocalAndRemote(outgoingMessage);
            m_lastSentMessage = HandshakeType.ServerHelloDone;
        }
        private void AddCertificateMessage(RecordLayer outgoingMessages)
        {
            HandshakeProtocol protocol = new HandshakeProtocol();
            var certificateMessage = new CertificateMessage();
            certificateMessage.Certificate = LocalCertificate;
            protocol.SetHandshakeMessage(certificateMessage);
            byte[] outgoingMessage = protocol.HandShakeData;
            HashLocalAndRemote(outgoingMessage);
            outgoingMessages.AddHandshake(protocol);
            m_lastSentMessage = HandshakeType.Certificate;
        }
        private ServerHelloMessage CreateServerHelloMessage(CipherSuite[] cipherSuites)
        {
            var serverHelloMessage = new ServerHelloMessage();
            serverHelloMessage.Version = m_secureChannel.ProtocolVersion;
            serverHelloMessage.Random = new byte[RandomNumberLength];
            m_rng.GetBytes(serverHelloMessage.Random);

            SecurityParameters.ServerRandom = serverHelloMessage.Random;

            //客户端没有传sessionid则生成一个新的sessionid
            if (this.SessionID.Length == 0) this.SessionID = Encoding.ASCII.GetBytes(Guid.NewGuid().ToString("N"));

            serverHelloMessage.SessionID = this.SessionID;

            // in case there is no match the server will return this default
            serverHelloMessage.CipherSuite = CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA;

            foreach (var cipherSuite in cipherSuites)
            {
                if (AllowedCipherSuites.Contains(cipherSuite))
                {
                    serverHelloMessage.CipherSuite = cipherSuite;
                    SetCipherSuite(cipherSuite);
                    break;
                }
            }
            return serverHelloMessage;
        }

        private void AddServerHelloMessage(RecordLayer outgoingMessages, CipherSuite[] cipherSuites)
        {
            HandshakeProtocol protocol = new HandshakeProtocol();
            var serverHelloMessage = CreateServerHelloMessage(cipherSuites);
            protocol.SetHandshakeMessage(serverHelloMessage);
            byte[] outgoingMessage = protocol.HandShakeData;
            HashLocalAndRemote(outgoingMessage);
            outgoingMessages.AddHandshake(protocol);
            m_lastSentMessage = HandshakeType.ServerHello;
        }
        /// <exception cref="NetMQSecurityException">The server hello message must not be received while expecting a different message.</exception>
        private void OnServerHello(HandshakeProtocol protocol)
        {
            ServerHelloMessage message = protocol.HandshakeMessage as ServerHelloMessage;
            Debug.Assert(message != null);

            if (m_lastReceivedMessage != HandshakeType.HelloRequest || m_lastSentMessage != HandshakeType.ClientHello)
            {
                throw new NetMQSecurityException(NetMQSecurityErrorCode.HandshakeUnexpectedMessage, "Server Hello received when expecting another message");
            }

            HashLocalAndRemote(protocol);

            NegotiateVersioin(message.Version);

            //*会话ID：用于表示客户端和服务端之间的会话。若客户端提供了会话ID，则可以校验是否与历史会话匹配。
            //  *若不匹配，则服务端可以选择直接使用客户端的会话ID或根据自定义规则生成一个新的会话ID，客户端需要保存服务端返回的会话ID当作本次会话的ID。
            //  *若匹配，则可以直接执行1 - RTT握手流程，返回ServerHello后直接返回`ChangeCipherSpec`和`Finished`消息。
            //暂时都走完全握手流程，这样安全性
            bool result = FindSession(message.SessionID);
            this.SessionID = message.SessionID;
            SecurityParameters.ServerRandom = message.Random;


#if DEBUG
            Debug.WriteLine("Session ID:  " + BitConverter.ToString(message.Random));
            Debug.WriteLine("RandomCookie:  " + BitConverter.ToString(this.SessionID));
#endif
            SetCipherSuite(message.CipherSuite);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="sessionID"></param>
        /// <returns></returns>
        private bool FindSession(byte[] sessionID)
        {
            //暂时都走完全握手流程
            return false;
        }
        private void OnCertificate(CertificateMessage message)
        {
            //Awlays return false.
            if (!VerifyCertificate(message.Certificate))
            {
                throw new NetMQSecurityException(NetMQSecurityErrorCode.HandshakeUnexpectedMessage, "Unable to verify certificate");
            }

            RemoteCertificate = message.Certificate;
        }

        private void OnCertificate(HandshakeProtocol protocol)
        {
            CertificateMessage message = protocol.HandshakeMessage as CertificateMessage;
            Debug.Assert(message != null);
            if (m_lastReceivedMessage != HandshakeType.ServerHello || m_lastSentMessage != HandshakeType.ClientHello)
            {
                throw new NetMQSecurityException(NetMQSecurityErrorCode.HandshakeUnexpectedMessage, "Certificate received when expecting another message");
            }

            HashLocalAndRemote(protocol);
            OnCertificate(message);
        }


        private void OnServerHelloDone(HandshakeProtocol protocol, IList<RecordLayer> outgoingMessages)
        {
            ServerHelloDoneMessage message = protocol.HandshakeMessage as ServerHelloDoneMessage;
            Debug.Assert(message != null);
            if (m_lastReceivedMessage != HandshakeType.Certificate || m_lastSentMessage != HandshakeType.ClientHello)
            {
                throw new NetMQSecurityException(NetMQSecurityErrorCode.HandshakeUnexpectedMessage, "Server Hello Done received when expecting another message");
            }

            HashLocalAndRemote(protocol);

            outgoingMessages.Add(AddClientKeyExchange());

            outgoingMessages.Add(InvokeChangeCipherSuite());

            outgoingMessages.Add(AddFinished());
        }
        private ClientKeyExchangeMessage CreateClientKeyExchangeMessage()

        {
            //struct {
            //      ProtocolVersion client_version;
            //    opaque random[46];
            //}PreMasterSecret;
            var premasterSecret = new byte[ClientKeyExchangeMessage.PreMasterSecretLength];

            // The version number in the PreMasterSecret is the version
            // offered by the client in the ClientHello.client_version, not the
            // version negotiated for the connection.  This feature is designed to
            // prevent rollback attacks.Unfortunately, some old implementations
            // use the negotiated version instead, and therefore checking the
            // version number may lead to failure to interoperate with such
            // incorrect client implementations.
            // Client implementations MUST always send the correct version number in
            // PreMasterSecret.If ClientHello.client_version is TLS 1.1 or higher,
            // server implementations MUST check the version number as described in
            // the note below.If the version number is TLS 1.0 or earlier, server
            // implementations SHOULD check the version number, but MAY have a
            // configuration option to disable the check.
            premasterSecret[0] = 3;
            premasterSecret[1] = 3;
            byte[] random = new byte[46];
            m_rng.GetBytes(random);


            Buffer.BlockCopy(random, 0, premasterSecret, 2, random.Length);


            var rsa = RemoteCertificate.PublicKey.Key as RSACryptoServiceProvider;
            var clientKeyExchangeMessage = new ClientKeyExchangeMessage();
            clientKeyExchangeMessage.EncryptedPreMasterSecret = rsa.Encrypt(premasterSecret, false);

            GenerateMasterSecret(premasterSecret);
            return clientKeyExchangeMessage;
        }
        private RecordLayer AddClientKeyExchange()
        {
            RecordLayer recordLayer = m_secureChannel.CreateRecordLayer();
            var clientKeyExchangeMessage = CreateClientKeyExchangeMessage();
            HandshakeProtocol protocol = new HandshakeProtocol();
            protocol.SetHandshakeMessage(clientKeyExchangeMessage);
            byte[] outgoingMessage = protocol.HandShakeData;
            HashLocalAndRemote(outgoingMessage);
            recordLayer.AddHandshake(protocol);
            m_lastSentMessage = HandshakeType.ClientKeyExchange;
            return recordLayer;
        }
        private void OnClientKeyExchange(ClientKeyExchangeMessage message)
        {
            var rsa = LocalCertificate.PrivateKey as RSACryptoServiceProvider;

            byte[] premasterSecret = rsa.Decrypt(message.EncryptedPreMasterSecret, false);
            GenerateMasterSecret(premasterSecret);

        }

        private void OnClientKeyExchange(HandshakeProtocol protocol, IList<RecordLayer>  outRecordLayers)
        {
            ClientKeyExchangeMessage message = protocol.HandshakeMessage as ClientKeyExchangeMessage;
            Debug.Assert(message != null);
            if (m_lastReceivedMessage != HandshakeType.ClientHello || m_lastSentMessage != HandshakeType.ServerHelloDone)
            {
                throw new NetMQSecurityException(NetMQSecurityErrorCode.HandshakeUnexpectedMessage, "Client Key Exchange received when expecting another message");
            }

            HashLocalAndRemote(protocol);

            OnClientKeyExchange(message);

            outRecordLayers.Add(InvokeChangeCipherSuite());
        }
        private void OnFinished(FinishedMessage message)
        {
            m_remoteHash.TransformFinalBlock(EmptyArray<byte>.Instance, 0, 0);

            byte[] seed = m_remoteHash.Hash;

#if NET40
            m_remoteHash.Dispose();
#else
            m_remoteHash.Clear();
#endif
            m_remoteHash = null;

            var label = SecurityParameters.Entity == ConnectionEnd.Client ? ServerFinishedLabel : ClientFinshedLabel;

            var verifyData = PRF.Get(SecurityParameters.MasterSecret, label, seed, FinishedMessage.VerifyDataLength);

#if DEBUG

            Debug.WriteLine("["+ (SecurityParameters.Entity == ConnectionEnd.Client ? "server":"client")+" verify_data]:" + BitConverter.ToString(verifyData));
#endif
            if (!verifyData.SequenceEqual(message.VerifyData))
            {
                throw new NetMQSecurityException(NetMQSecurityErrorCode.HandshakeVerifyData, "peer verify data wrong");
            }

        }


        /// <exception cref="NetMQSecurityException">The Finished message must not be received while expecting a another message.</exception>
        /// <exception cref="NetMQSecurityException">The peer verification data must be valid.</exception>
        private RecordLayer OnFinished(HandshakeProtocol protocol)
        {
            FinishedMessage message = protocol.HandshakeMessage as FinishedMessage;
            Debug.Assert(message != null);
            if (
                (SecurityParameters.Entity == ConnectionEnd.Client &&
                 (!m_secureChannel.ChangeSuiteChangeArrived ||
                  m_lastReceivedMessage != HandshakeType.ServerHelloDone || m_lastSentMessage != HandshakeType.Finished)) ||
                (SecurityParameters.Entity == ConnectionEnd.Server &&
                 (!m_secureChannel.ChangeSuiteChangeArrived ||
                  m_lastReceivedMessage != HandshakeType.ClientKeyExchange || m_lastSentMessage != HandshakeType.ServerHelloDone)))
            {
                throw new NetMQSecurityException(NetMQSecurityErrorCode.HandshakeUnexpectedMessage, "Finished received when expecting another message");
            }

            if (SecurityParameters.Entity == ConnectionEnd.Server)
            {
                HashLocal(protocol);
            }
            OnFinished(message);
            RecordLayer outgoingMessages = null;
            if (SecurityParameters.Entity == ConnectionEnd.Server)
            {
                outgoingMessages = AddFinished();
#if DEBUG
                Debug.WriteLine("[finish]");
#endif
            }

            m_done = true;
            return outgoingMessages;
        }
        private FinishedMessage CreateFinishedMessage()
        {
            m_localHash.TransformFinalBlock(EmptyArray<byte>.Instance, 0, 0);

            byte[] seed = m_localHash.Hash;
#if NET40
            m_localHash.Dispose();
#endif
            m_localHash = null;

            var label = SecurityParameters.Entity == ConnectionEnd.Server ? ServerFinishedLabel : ClientFinshedLabel;

            var finishedMessage = new FinishedMessage();
            finishedMessage.VerifyData = PRF.Get(SecurityParameters.MasterSecret, label, seed, FinishedMessage.VerifyDataLength);
#if DEBUG
            Debug.WriteLine("[verify_data]:" + BitConverter.ToString(finishedMessage.VerifyData));
#endif
            return finishedMessage;
        }

        private RecordLayer AddFinished()
        {
            RecordLayer recordLayer = m_secureChannel.CreateRecordLayer();
            HandshakeProtocol protocol = new HandshakeProtocol();
            FinishedMessage finishedMessage = CreateFinishedMessage();
            //未设置加密，procotol是明文，握手时需要明文
            protocol.SetHandshakeMessage(finishedMessage);
            //原始数据
            byte[] outgoingMessage = protocol.HandShakeData;
            recordLayer.AddHandshake(protocol);
            //数据加密
            protocol.HandShakeData = new ReadonlyBuffer<byte>(m_secureChannel.Context.EncryptMessage(recordLayer.ContentType, outgoingMessage));
            //设置HandShakeData 数据加密
            protocol.IsEncrypted = true;
            m_lastSentMessage = HandshakeType.Finished;

            if (SecurityParameters.Entity == ConnectionEnd.Client)
            {
                //需要hash的是原始数据
                HashRemote(outgoingMessage);
            }
            return recordLayer;
        }

        /// <exception cref="ArgumentOutOfRangeException">cipher must have a valid value.</exception>
        private void SetCipherSuite(CipherSuite cipher)
        {
            switch (cipher)
            {
                case CipherSuite.TLS_NULL_WITH_NULL_NULL:
                case CipherSuite.TLS_RSA_WITH_NULL_SHA:
                case CipherSuite.TLS_RSA_WITH_NULL_SHA256:
                    SecurityParameters.BulkCipherAlgorithm = BulkCipherAlgorithm.Null;
                    SecurityParameters.FixedIVLength = 0;
                    SecurityParameters.EncKeyLength = 0;
                    SecurityParameters.BlockLength = 0;
                    SecurityParameters.RecordIVLength = 0;
                    break;
                case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256:
                    SecurityParameters.BulkCipherAlgorithm = BulkCipherAlgorithm.AES;
                    SecurityParameters.FixedIVLength = 0;
                    SecurityParameters.EncKeyLength = 16;
                    SecurityParameters.BlockLength = 16;
                    SecurityParameters.RecordIVLength = 16;
                    break;
                case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
                    SecurityParameters.BulkCipherAlgorithm = BulkCipherAlgorithm.AES;
                    SecurityParameters.FixedIVLength = 0;
                    SecurityParameters.EncKeyLength = 32;
                    SecurityParameters.BlockLength = 16;
                    SecurityParameters.RecordIVLength = 16;
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(cipher));
            }

            switch (cipher)
            {
                case CipherSuite.TLS_NULL_WITH_NULL_NULL:
                    SecurityParameters.MACAlgorithm = MACAlgorithm.Null;
                    SecurityParameters.MACKeyLength = 0;
                    SecurityParameters.MACLength = 0;
                    break;
                case CipherSuite.TLS_RSA_WITH_NULL_SHA:
                case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA:
                    SecurityParameters.MACAlgorithm = MACAlgorithm.HMACSha1;
                    SecurityParameters.MACKeyLength = 20;
                    SecurityParameters.MACLength = 20;
                    break;
                case CipherSuite.TLS_RSA_WITH_NULL_SHA256:
                case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
                    SecurityParameters.MACAlgorithm = MACAlgorithm.HMACSha256;
                    SecurityParameters.MACKeyLength = 32;
                    SecurityParameters.MACLength = 32;
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(cipher));
            }
        }

        /// <summary>
        /// Raise the CipherSuiteChange event.
        /// </summary>
        private RecordLayer InvokeChangeCipherSuite()
        {
            RecordLayer recordLayer = m_secureChannel.CreateRecordLayer();
            ChangeCipherSpecProtocol protocol = new ChangeCipherSpecProtocol();
            recordLayer.AddChangeCipherSpecProtocol(protocol);
            // The change cipher spec protocol exists to signal transitions in ciphering strategies.
            // The protocol consists of a single message, which is encrypted and compressed under the current(not the pending) connection state. 
            // The message consists of a single byte of value 1.
            // enum { change_cipher_spec(1), (255) } type;
            CipherSuiteChange?.Invoke(this, EventArgs.Empty);
            return recordLayer;
        }
        private void GenerateMasterSecret(byte[] preMasterSecret)
        {
            var seed = new byte[RandomNumberLength*2];

            Buffer.BlockCopy(SecurityParameters.ClientRandom, 0, seed, 0, RandomNumberLength);
            Buffer.BlockCopy(SecurityParameters.ServerRandom, 0, seed, RandomNumberLength, RandomNumberLength);

            SecurityParameters.MasterSecret =
                PRF.Get(preMasterSecret, MasterSecretLabel, seed, MasterSecretLength);

#if DEBUG

            Debug.WriteLine("[preMasterSecret]:" + BitConverter.ToString(preMasterSecret));
            Debug.WriteLine("[ClientRandom]:" + BitConverter.ToString(SecurityParameters.ClientRandom));
            Debug.WriteLine("[ServerRandom]:" + BitConverter.ToString(SecurityParameters.ServerRandom));
            Debug.WriteLine("[MasterSecret]:" + BitConverter.ToString(SecurityParameters.MasterSecret));
#endif
            Array.Clear(preMasterSecret, 0, preMasterSecret.Length);
        }

        /// <summary>
        /// 更新sessionid
        /// </summary>
        /// <param name="sessionId"></param>
        public void UpdateSessionId(byte[] sessionId)
        {
            SessionID = sessionId;
        }
        /// <summary>
        /// Dispose of any contained resources.
        /// </summary>
        public void Dispose()
        {
            if (m_rng != null)
            {
#if NET40
                m_rng.Dispose();
#endif
                m_rng = null;
            }

            if (m_remoteHash != null)
            {
#if NET40
                m_remoteHash.Dispose();
#endif
                m_remoteHash = null;
            }

            if (m_localHash != null)
            {
#if NET40
                m_localHash.Dispose();
#endif
                m_localHash = null;
            }

            if (m_prf != null)
            {
                m_prf.Dispose();
                m_prf = null;
            }
        }
    }
}