using System;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using NetMQ.Security.Extensions;
using NetMQ.Security.V0_1.HandshakeMessages;

namespace NetMQ.Security.V0_1
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
        private HandshakeType m_lastReceivedMessage = HandshakeType.HelloRequest;

        /// <summary>
        /// This serves to remember which HandshakeType was last sent.
        /// </summary>
        private HandshakeType m_lastSentMessage = HandshakeType.HelloRequest;

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
        /// 当前使用的子版本。
        /// 3.3是标准的TLS1.2版本协议。
        /// </summary>
        public ProtocolVersion SubProtocolVersion { get; private set; }
        /// <summary>
        /// Given an incoming handshake-protocol message, route it to the corresponding handler.
        /// </summary>
        /// <param name="incomingMessage">the NetMQMessage that has come in</param>
        /// <param name="outgoingMessages">a collection of NetMQMessages that are to be sent</param>
        /// <returns>true if finished - ie, an incoming message of type Finished was received</returns>
        /// <exception cref="ArgumentNullException"><paramref name="incomingMessage"/> must not be <c>null</c>.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="incomingMessage"/> must have a valid <see cref="HandshakeType"/>.</exception>
        public bool ProcessMessages(NetMQMessage incomingMessage, OutgoingMessageBag outgoingMessages)
        {
            if (incomingMessage == null)
            {
                if (m_lastReceivedMessage == m_lastSentMessage &&
                    m_lastSentMessage == HandshakeType.HelloRequest &&
                    SecurityParameters.Entity == ConnectionEnd.Client)
                {
                    //客户端发送握手
                    OnHelloRequest(outgoingMessages);
                    return false;
                }
                else
                {
                    throw new ArgumentNullException(nameof(incomingMessage));
                }
            }

#if DEBUG
            int size = incomingMessage.Sum(f => f.BufferSize);
            Debug.WriteLine("[handshake(" + size + ")]:");
            byte[] data = new byte[size];
            int offset = 0;
            foreach (var frame in incomingMessage)
            {
                Buffer.BlockCopy(frame.Buffer, 0, data, offset, frame.BufferSize);
            }
            Debug.WriteLine(BitConverter.ToString(data));
#endif

            //A Finished message is always sent immediately after a change cipher spec message to verify that the key exchange and authentication processes were successful.  
            //It is essential that a change cipher spec message be received between the other handshake messages and the Finished message.
            //已经收到ChangeCipherSuite，接下来就是Finish
            HandshakeType handshakeType;

            if (m_secureChannel.ChangeSuiteChangeArrived)
            {
                handshakeType = HandshakeType.Finished;
            }
            else
            {
                handshakeType = (HandshakeType)incomingMessage[0].Buffer[0];
                ////起始计数从0开始，Finished在解密的时候会添加计数，其他record层都要在这里添加读计数
                //m_secureChannel.RecordLayer.GetAndIncreaseReadSequneceNumber();
            }

            switch (handshakeType)
            {
                case HandshakeType.HelloRequest:
                    {
                        //接收到对端的HelloRequest重新协商。暂时抛出异常重置连接
                        NetMQMessage alert = m_secureChannel.HandshakeFailure(AlertLevel.Fatal, m_secureChannel.ProtocolVersion);
                        //抛出异常，返回alert协议，通知客户端断开连接。
                        throw new AlertException(alert, new Exception(AlertDescription.NoRenegotiation.ToString()));
                    }
                case HandshakeType.ClientHello:
                    OnClientHello(incomingMessage, outgoingMessages);
                    break;
                case HandshakeType.ServerHello:
                    OnServerHello(incomingMessage);
                    break;
                case HandshakeType.Certificate:
                    OnCertificate(incomingMessage);
                    break;
                case HandshakeType.ServerHelloDone:
                    OnServerHelloDone(incomingMessage, outgoingMessages);
                    break;
                case HandshakeType.ClientKeyExchange:
                    OnClientKeyExchange(incomingMessage);
                    break;
                case HandshakeType.Finished:
                    OnFinished(incomingMessage, outgoingMessages);
                    break;
                default:
                    {
                        NetMQMessage alert = m_secureChannel.HandshakeFailure(AlertLevel.Fatal, m_secureChannel.ProtocolVersion);
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
        private void HashLocalAndRemote(NetMQMessage message)
        {
            foreach (var frame in message)
            {
                HashLocal(frame.Buffer);
                HashRemote(frame.Buffer);
            }
        }

        /// <summary>
        /// Use the local (as opposed to that of the remote-peer) hashing algorithm to compute a hash
        /// of the frames within the given NetMQMessage.
        /// </summary>
        /// <param name="message">the NetMQMessage whose frames are to be hashed</param>
        private void HashLocal(NetMQMessage message)
        {
            foreach (var frame in message)
            {
                HashLocal(frame.Buffer);
            }
        }

        /// <summary>
        /// Use the local (as opposed to that of the remote-peer) hashing algorithm to compute a hash
        /// of the frames within the given NetMQMessage.
        /// </summary>
        /// <param name="message">the NetMQMessage whose frames are to be hashed</param>
        private void HashLocal(byte[] message)
        {
            Hash(m_localHash, message);
        }

        /// <summary>
        /// Use the remote-peer hashing algorithm to compute a hash
        /// of the frames within the given NetMQMessage.
        /// </summary>
        /// <param name="message">the NetMQMessage whose frames are to be hashed</param>
        private void HashRemote(byte[] message)
        {
            Hash(m_remoteHash, message);
        }
        private void HashRemote(NetMQMessage message)
        {
            foreach (var frame in message)
            {
                Hash(m_remoteHash, frame.Buffer);
            }
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
        private void OnHelloRequest(OutgoingMessageBag outgoingMessages)
        {
            //客户端根据配置决定握手层版本号
            var clientHelloMessage = new ClientHelloMessage();
            clientHelloMessage.RandomNumber = new byte[RandomNumberLength];

            clientHelloMessage.SessionID = SessionID;

            m_rng.GetBytes(clientHelloMessage.RandomNumber);
            ////TODO: 测试

            //string random = "5e c2 54 f6 fa cc f1 40 be ec 3b 43 44 1c 72 c3 25 ed 43 7a 5d cf a2 17 33 26 94 48 f7 cb 34 f9";
            //clientHelloMessage.RandomNumber = random.ConvertHexToByteArray();
            SecurityParameters.ClientRandom = clientHelloMessage.RandomNumber;

            clientHelloMessage.CipherSuites = AllowedCipherSuites;

            NetMQMessage outgoingMessage = clientHelloMessage.ToNetMQMessage();
            
            HashLocalAndRemote(outgoingMessage);

            //第一个record的seqnum从0开始
            outgoingMessages.AddHandshakeMessage(outgoingMessage);
            m_lastSentMessage = HandshakeType.ClientHello;
        }

        /// <exception cref="NetMQSecurityException">The client hello message must not be received while expecting a different message.</exception>
        private void OnClientHello(NetMQMessage incomingMessage, OutgoingMessageBag outgoingMessages)
        {
            if (m_lastReceivedMessage != HandshakeType.HelloRequest || m_lastSentMessage != HandshakeType.HelloRequest)
            {
                throw new NetMQSecurityException(NetMQSecurityErrorCode.HandshakeUnexpectedMessage, "Client Hello received when expecting another message");
            }

            HashLocalAndRemote(incomingMessage);

            var handShakeTypeFrame = incomingMessage.Pop();
            //服务端根据主版本号先判断
            var handShakeLengthFrame = incomingMessage.Pop();
            NetMQFrame versionFrame = incomingMessage.Pop();
            SubProtocolVersion = (ProtocolVersion)versionFrame.Buffer;

            if (!this.m_secureChannel.Configuration.SupposeProtocolVersions.Any(v => v.Equals(SubProtocolVersion)))
            {
                throw new NetMQSecurityException(NetMQSecurityErrorCode.InvalidProtocolVersion, "the hand shake protocol version is not supposed");
            }
            //获取保存子协议版本
            var clientHelloMessage = new ClientHelloMessage();

            clientHelloMessage.SetFromNetMQMessage(incomingMessage);
            //获取到客户端的sessionid
            this.SessionID = clientHelloMessage.SessionID;
            SecurityParameters.ClientRandom = clientHelloMessage.RandomNumber;

            AddServerHelloMessage(outgoingMessages, clientHelloMessage.CipherSuites);

            AddCertificateMessage(outgoingMessages);

            AddServerHelloDone(outgoingMessages);
        }

        private void AddServerHelloDone(OutgoingMessageBag outgoingMessages)
        {
            var serverHelloDoneMessage = new ServerHelloDoneMessage();
            NetMQMessage outgoingMessage = serverHelloDoneMessage.ToNetMQMessage();
            HashLocalAndRemote(outgoingMessage);
            outgoingMessages.AddHandshakeMessage(outgoingMessage);
            m_lastSentMessage = HandshakeType.ServerHelloDone;
        }

        private void AddCertificateMessage(OutgoingMessageBag outgoingMessages)
        {
            var certificateMessage = new CertificateMessage ();
            certificateMessage.Certificate = LocalCertificate;
            NetMQMessage outgoingMessage = certificateMessage.ToNetMQMessage();
            HashLocalAndRemote(outgoingMessage);
            outgoingMessages.AddHandshakeMessage(outgoingMessage);
            m_lastSentMessage = HandshakeType.Certificate;
        }

        private void AddServerHelloMessage(OutgoingMessageBag outgoingMessages, CipherSuite[] cipherSuites)
        {
            var serverHelloMessage = new ServerHelloMessage ();
            serverHelloMessage.RandomNumber = new byte[RandomNumberLength];
            m_rng.GetBytes(serverHelloMessage.RandomNumber);


            ////TODO: 测试

            //string random = "ae f1 ba 12 3a 54 3c 51 7b 3d 49 87 05 80 6e 67 45 c5 76 77 74 26 01 d9 b9 da 69 79 e2 84 1d 37";
            //serverHelloMessage.RandomNumber = random.ConvertHexToByteArray();

            SecurityParameters.ServerRandom = serverHelloMessage.RandomNumber;

            //客户端没有传sessionid则生成一个新的sessionid
            if (this.SessionID.Length == 0) this.SessionID = Encoding.ASCII.GetBytes(Guid.NewGuid().ToString("N"));

            ////TODO: 测试

            //this.SessionID = "37 61 36 36 35 64 37 38 36 62 61 36 34 32 62 64 38 36 61 62 32 61 63 39 36 31 35 34 37 34 33 61".ConvertHexToByteArray();

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

            NetMQMessage outgoingMessage = serverHelloMessage.ToNetMQMessage();
            HashLocalAndRemote(outgoingMessage);
            outgoingMessages.AddHandshakeMessage(outgoingMessage);
            m_lastSentMessage = HandshakeType.ServerHello;
        }

        /// <exception cref="NetMQSecurityException">The server hello message must not be received while expecting a different message.</exception>
        private void OnServerHello(NetMQMessage incomingMessage)
        {
            if (m_lastReceivedMessage != HandshakeType.HelloRequest || m_lastSentMessage != HandshakeType.ClientHello)
            {
                throw new NetMQSecurityException(NetMQSecurityErrorCode.HandshakeUnexpectedMessage, "Server Hello received when expecting another message");
            }

            HashLocalAndRemote(incomingMessage);

            var handShakeTypeFrame = incomingMessage.Pop();
            //服务端根据主版本号先判断
                //标准的获取长度和版本号，并校验
            var handShakeLengthFrame = incomingMessage.Pop();
            NetMQFrame versionFrame = incomingMessage.Pop();
            SubProtocolVersion = (ProtocolVersion)versionFrame.Buffer;
            if (!this.m_secureChannel.Configuration.SupposeProtocolVersions.Any(v => v.Equals(SubProtocolVersion)))
            {
                throw new NetMQSecurityException(NetMQSecurityErrorCode.InvalidProtocolVersion, "the hand shake protocol version is not supposed");
            }
            var serverHelloMessage =  new ServerHelloMessage();
            serverHelloMessage.SetFromNetMQMessage(incomingMessage);
            this.SessionID = serverHelloMessage.SessionID;
            SecurityParameters.ServerRandom = serverHelloMessage.RandomNumber;

            SetCipherSuite(serverHelloMessage.CipherSuite);
        }

        /// <exception cref="NetMQSecurityException">Must be able to verify the certificate.</exception>
        /// <exception cref="NetMQSecurityException">The certificate message must not be received while expecting a another message.</exception>
        private void OnCertificate(NetMQMessage incomingMessage)
        {
            if (m_lastReceivedMessage != HandshakeType.ServerHello || m_lastSentMessage != HandshakeType.ClientHello)
            {
                throw new NetMQSecurityException(NetMQSecurityErrorCode.HandshakeUnexpectedMessage, "Certificate received when expecting another message");
            }

            HashLocalAndRemote(incomingMessage);

            var handShakeTypeFrame = incomingMessage.Pop();
            var certificateMessage = new CertificateMessage();
            certificateMessage.SetFromNetMQMessage(incomingMessage);

            //Awlays return false.
            if (!VerifyCertificate(certificateMessage.Certificate))
            {
                throw new NetMQSecurityException(NetMQSecurityErrorCode.HandshakeUnexpectedMessage, "Unable to verify certificate");
            }

            RemoteCertificate = certificateMessage.Certificate;
        }

        /// <exception cref="NetMQSecurityException">The server hello message must not be received while expecting another message.</exception>
        private void OnServerHelloDone(NetMQMessage incomingMessage,
            OutgoingMessageBag outgoingMessages)
        {
            if (m_lastReceivedMessage != HandshakeType.Certificate || m_lastSentMessage != HandshakeType.ClientHello)
            {
                throw new NetMQSecurityException(NetMQSecurityErrorCode.HandshakeUnexpectedMessage, "Server Hello Done received when expecting another message");
            }

            HashLocalAndRemote(incomingMessage);

            var handShakeTypeFrame = incomingMessage.Pop();
            var serverHelloDoneMessage =  new ServerHelloDoneMessage();
            serverHelloDoneMessage.SetFromNetMQMessage(incomingMessage);

            AddClientKeyExchange(outgoingMessages);

            InvokeChangeCipherSuite();

            AddFinished(outgoingMessages);
        }

        private void AddClientKeyExchange(OutgoingMessageBag outgoingMessages)
        {
            var clientKeyExchangeMessage =  new ClientKeyExchangeMessage();
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
            ////TODO :测试
            //premasterSecret = "03-03-11-41-D4-8F-8C-62-6F-31-12-40-D8-1D-F3-1C-8C-E3-6D-2F-0E-87-C6-DA-D1-17-96-CF-91-CD-EC-DB-F9-B5-52-FB-66-B6-E6-EB-65-71-1F-7A-05-25-0B-03".ConvertHexToByteArray('-');
            var rsa = RemoteCertificate.PublicKey.Key as RSACryptoServiceProvider;
            clientKeyExchangeMessage.EncryptedPreMasterSecret = rsa.Encrypt(premasterSecret, false);

            GenerateMasterSecret(premasterSecret);

            NetMQMessage outgoingMessage = clientKeyExchangeMessage.ToNetMQMessage();
            HashLocalAndRemote(outgoingMessage);
            outgoingMessages.AddHandshakeMessage(outgoingMessage);
            m_lastSentMessage = HandshakeType.ClientKeyExchange;
        }

        /// <exception cref="NetMQSecurityException">The client key exchange must not be received while expecting a another message.</exception>
        private void OnClientKeyExchange(NetMQMessage incomingMessage)
        {
            if (m_lastReceivedMessage != HandshakeType.ClientHello || m_lastSentMessage != HandshakeType.ServerHelloDone)
            {
                throw new NetMQSecurityException(NetMQSecurityErrorCode.HandshakeUnexpectedMessage, "Client Key Exchange received when expecting another message");
            }

            HashLocalAndRemote(incomingMessage);

            var handShakeTypeFrame = incomingMessage.Pop();
            var clientKeyExchangeMessage = new ClientKeyExchangeMessage();
            clientKeyExchangeMessage.SetFromNetMQMessage(incomingMessage);

            var rsa = LocalCertificate.PrivateKey as RSACryptoServiceProvider;

            byte[] premasterSecret = rsa.Decrypt(clientKeyExchangeMessage.EncryptedPreMasterSecret, false);
            GenerateMasterSecret(premasterSecret);

            InvokeChangeCipherSuite();
        }

        /// <exception cref="NetMQSecurityException">The Finished message must not be received while expecting a another message.</exception>
        /// <exception cref="NetMQSecurityException">The peer verification data must be valid.</exception>
        private void OnFinished(NetMQMessage incomingMessage, OutgoingMessageBag outgoingMessages)
        {
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
                HashLocal(incomingMessage);
            }

            var finishedMessage = new FinishedMessage();
            finishedMessage.SetFromNetMQMessage(incomingMessage);

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

            Debug.WriteLine("[verify_data]:" + BitConverter.ToString(verifyData));
#endif
            if (!verifyData.SequenceEqual(finishedMessage.VerifyData))
            {
                throw new NetMQSecurityException(NetMQSecurityErrorCode.HandshakeVerifyData, "peer verify data wrong");
            }

            if (SecurityParameters.Entity == ConnectionEnd.Server)
            {
                AddFinished(outgoingMessages);
#if DEBUG
                Debug.WriteLine("[finish]");
#endif
            }

            m_done = true;
        }

        private void AddFinished(OutgoingMessageBag outgoingMessages)
        {
            m_localHash.TransformFinalBlock(EmptyArray<byte>.Instance, 0, 0);

            byte[] seed = m_localHash.Hash;
#if NET40
            m_localHash.Dispose();
#endif
            m_localHash = null;

            var label = SecurityParameters.Entity == ConnectionEnd.Server ? ServerFinishedLabel : ClientFinshedLabel;

            var finishedMessage =  new FinishedMessage();
            finishedMessage.VerifyData = PRF.Get(SecurityParameters.MasterSecret, label, seed, FinishedMessage.VerifyDataLength);
#if DEBUG
            Debug.WriteLine("[verify_data]:" + BitConverter.ToString(finishedMessage.VerifyData));
#endif
            NetMQMessage outgoingMessage = finishedMessage.ToNetMQMessage();
            outgoingMessages.AddHandshakeMessage(outgoingMessage);
            m_lastSentMessage = HandshakeType.Finished;

            if (SecurityParameters.Entity == ConnectionEnd.Client)
            {
                HashRemote(outgoingMessage);
            }
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
        private void InvokeChangeCipherSuite()
        {
            CipherSuiteChange?.Invoke(this, EventArgs.Empty);
        }

        private void GenerateMasterSecret(byte[] preMasterSecret)
        {
            var seed = new byte[RandomNumberLength*2];

#if DEBUG

            Debug.WriteLine("[preMasterSecret]:" + BitConverter.ToString(preMasterSecret));
            Debug.WriteLine("[ClientRandom]:" + BitConverter.ToString(SecurityParameters.ClientRandom));
            Debug.WriteLine("[ServerRandom]:" + BitConverter.ToString(SecurityParameters.ServerRandom));
#endif
            Buffer.BlockCopy(SecurityParameters.ClientRandom, 0, seed, 0, RandomNumberLength);
            Buffer.BlockCopy(SecurityParameters.ServerRandom, 0, seed, RandomNumberLength, RandomNumberLength);

            SecurityParameters.MasterSecret =
                PRF.Get(preMasterSecret, MasterSecretLabel, seed, MasterSecretLength);

#if DEBUG

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