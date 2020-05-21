using System;

namespace NetMQ.Security.V0_1.HandshakeMessages
{
    /// <summary>
    /// This enum-type specifies what part of the SSL/TLS handshake-protocol;
    /// it may be one any of 10 values such as HelloRequest,  CertificateVerify, or Finished.
    /// </summary>
    public enum HandshakeType : byte
    {

        /// <summary>
        /// HelloRequest is a simple notification that the client should begin the negotiation process anew.  
        /// In response, the client should send a ClientHello message when convenient.  
        /// This message is intended to establish which side is the client or server but merely to initiate a new negotiation.Servers SHOULD NOT send a HelloRequest immediately upon the client's initial connection.
        /// It is the client's job to send a ClientHello at that time.
        /// This message will be ignored by the client if the client is currently negotiating a session.This message MAY be ignored by the client if it does not wish to renegotiate a session,  or the client may, if it wishes, respond with a no_renegotiation alert.
        /// Since handshake messages are intended to have transmission precedence over application data, it is expected that the negotiation will begin before no more than a few records are received from the client.  
        /// If the server sends a HelloRequest but does not receive a ClientHello in response, it may close the connection with a fatal alert.
        /// After sending a HelloRequest, servers SHOULD NOT repeat the request until the subsequent handshake negotiation is complete.
        /// </summary>
        HelloRequest = 0,
        /// <summary>This is what the client sends to initiate communication using the SSL handshake protocol.</summary>

        /// <summary>This is what the client sends to the server as it's initial step of the handshake-protocol.</summary>
        ClientHello = 1,

        /// <summary>This is that part of the handshake-protocol that the server sends to the client after that client has sent its client-hello message.</summary>
        ServerHello = 2,

        /// <summary>This denotes that part of the handshake-protocol in which a certificate is sent, along with the public key.</summary>
        Certificate = 11,

        /// <summary>This step is taken by the serve only when there is no public key shared along with the certificate.</summary>
        ServerKeyExchange = 12,

        /// <summary>This is that part of the handshake-protocol that the client sends when it needs to get authenticated by a client certificate.</summary>
        CertificateRequest = 13,

        /// <summary>This is sent by the server to tell the client that the server has finished sending its hello message and is waiting for a response from the client.</summary>
        ServerHelloDone = 14,

        /// <summary>This is that part of the handshake-protocol that denotes verification of a certificate.</summary>
        CertificateVerify = 15,

        /// <summary>This is only sent after the client calculates the premaster secret with the help of the random values of both the server and the client.</summary>
        ClientKeyExchange = 16,

        /// <summary>This is that part of the handshake-protocol that is sent to indicate readiness to exchange data</summary>
        Finished = 20
    }


    /// <summary>
    /// The abstract class HandshakeMessage holds a HandshakeType property and provides
    /// methods ToNetMQMessage and SetFromNetMQMessage, all intended to be overridden.
    /// </summary>
    internal abstract class HandshakeMessage
    {
        /// <summary>
        /// Get the part of the handshake-protocol that this HandshakeMessage represents.
        /// </summary>
        public abstract HandshakeType HandshakeType { get; }

        public virtual void SetFromNetMQMessage(NetMQMessage message)
        {
            throw new NotImplementedException();
        }

        public virtual NetMQMessage ToNetMQMessage()
        {
            throw new NotImplementedException();
        }
        /// <summary>
        /// Return a new NetMQMessage that holds a frame containing only one byte containing the HandshakeType.
        /// </summary>
        /// <returns>the HandshakeType wrapped in a new NetMQMessage</returns>
        protected NetMQMessage AddHandShakeType()
        {
            NetMQMessage message = new NetMQMessage();
            message.Append(new[] { (byte)HandshakeType });

            return message;
        }
        public void InsertLength(NetMQMessage message)
        {
            byte[] lengthBytes= new byte[3];
            GetLength(lengthBytes, message);
            message.Push(lengthBytes);
        }
        /// <summary>
        /// 获取NetMQFrame数组的总字节数,填充到lengthBytes中。
        /// </summary>
        /// <returns>the resulting new NetMQMessage</returns>
        /// <exception cref="ArgumentException">handshake的数据大小不能超过65535,因为协议使用2个字节存储长度。</exception>
        public virtual void GetLength(byte[] lengthBytes ,NetMQMessage message)
        {
            message.GetLength(lengthBytes);
        }
    }
}
