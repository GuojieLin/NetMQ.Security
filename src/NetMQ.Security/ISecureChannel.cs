using NetMQ.Security.Layer;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace NetMQ.Security
{
    /// <summary>
    /// This delegate defines a method signature that takes a PkixCertificate and returns a bool.
    /// </summary>
    /// <param name="certificate2">the PkixCertificate that is to do the verification</param>
    /// <returns>the result of the verification - which is true if it verifies ok, false if it fails verification</returns>
    public delegate bool VerifyCertificateDelegate(X509Certificate2 certificate2);

    /// <summary>
    /// Secure channel between a client and a server
    /// </summary>
    public interface ISecureChannel : IDisposable
    {
        /// <summary>
        /// Get whether the secure channel is ready to encrypt messages.
        /// </summary>
        bool SecureChannelReady { get; }

        /// <summary>
        /// Get or set the certificate of the server; for client this property is irrelevant.
        /// The certificate must include a private key.
        /// </summary>
        X509Certificate2 Certificate { get; set; }

        /// <summary>
        /// Get or set the array of allowed cipher suites for this secure channel, ordered by priority.
        /// </summary>
        CipherSuite[] AllowedCipherSuites { get; set; }

        /// <summary>
        /// Set the verify-certificate method. By default the certificate is validated by the certificate chain.
        /// </summary>
        /// <param name="verifyCertificate">Delegate for the verify certificate method</param>
        void SetVerifyCertificate(VerifyCertificateDelegate verifyCertificate);

        /// <summary>
        /// Process handshake and change cipher suite messages. This method should be called for every incoming message until the method returns true.
        /// You cannot encrypt or decrypt messages until the method return true.
        /// Each call to the method may include outgoing messages that need to be sent to the other peer.
        /// </summary>
        /// <param name="incomingMessage">The incoming message from the other peer</param>
        /// <param name="outgoingMesssages">Outgoing messages that need to be sent to the other peer</param>
        /// <returns>Return true when the method completes the handshake stage and the SecureChannel is ready to encrypt and decrypt messages</returns>
        [Obsolete("不再使用NetMQMessage解析TLS协议RecordLayer层")]
        bool ProcessMessage(NetMQMessage incomingMessage, IList<NetMQMessage> outgoingMesssages);

        bool ProcessMessage(RecordLayer inRecordLayer, IList<RecordLayer> outRecordLayers);

        /// <summary>
        /// Encrypt application Message
        /// </summary>
        /// <param name="plainMessage">The plain message</param>
        /// <returns>The cipher message</returns>
        [Obsolete("不再使用NetMQMessage解析TLS协议RecordLayer层")]
        NetMQMessage EncryptApplicationMessage(NetMQMessage plainMessage);

        /// <summary>
        /// Decrypt application message
        /// </summary>
        /// <param name="cipherMessage">The cipher message</param>
        /// <returns>The decrypted message</returns>
        [Obsolete("不再使用NetMQMessage解析TLS协议RecordLayer层")]
        NetMQMessage DecryptApplicationMessage(NetMQMessage cipherMessage);

        /// <summary>
        /// Encrypt application Message
        /// </summary>
        /// <param name="plainMessage">The plain message</param>
        /// <returns>The cipher message</returns>
        byte[] EncryptApplicationBytes(byte[] plainMessage);
        byte[] EncryptApplicationData(ReadonlyBuffer<byte> plainMessage);

        /// <summary>
        /// Decrypt application message
        /// </summary>
        /// <param name="cipherMessage">The cipher message</param>
        /// <returns>The decrypted message</returns>
        byte[] DecryptApplicationBytes(byte[] cipherMessage);
        byte[] DecryptApplicationData(ReadonlyBuffer<byte> cipherMessage);
    }
}