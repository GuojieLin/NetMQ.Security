using NetMQ.Security.V0_1.HandshakeMessages;
using System;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;

namespace NetMQ.Security.V0_2.HandshakeMessages
{
    /// <summary>
    /// The CertificateMessage is a type of HandshakeMessage with a HandshakeType of Certificate.
    /// It holds a Certificate, and overrides SetFromNetMQMessage and ToNetMQMessage to read/write the certificate
    /// from the frames of a NetMQMessage.
    /// </summary>
    internal class CertificateMessage : V0_1.HandshakeMessages.CertificateMessage
    {
        /// <summary>
        /// Remove the two frames from the given NetMQMessage, interpreting them thusly:
        /// 1. a byte with the HandshakeType,
        /// 2. a byte-array containing the X.509 digital certificate.
        /// </summary>
        /// <param name="message">a NetMQMessage - which must have 2 frames</param>
        /// <exception cref="NetMQSecurityException"><see cref="NetMQSecurityErrorCode.InvalidFramesCount"/>: FrameCount must be 1.</exception>
        public override void SetFromNetMQMessage(NetMQMessage message)
        {
            NetMQFrame lengthFrame = message.Pop();
            NetMQFrame certslengthFrame = message.Pop();
            NetMQFrame certlengthFrame = message.Pop();
            base.SetFromNetMQMessage(message);
        }

        /// <summary>
        /// Return a new NetMQMessage that holds two frames:
        /// 1. a frame with a single byte representing the HandshakeType, which is Certificate,
        /// 2. a frame containing the certificate that has been exported to a byte-array.
        /// </summary>
        /// <returns>the resulting new NetMQMessage</returns>
        public override NetMQMessage ToNetMQMessage()
        {
            NetMQMessage message = AddHandShakeType();
            byte[] certBytes = Certificate.Export(X509ContentType.Cert);
            //加长度,证书总长度
            var certsLengthBytes = BitConverter.GetBytes(certBytes.Length+3);
            message.Append(new byte[] { certsLengthBytes[2], certsLengthBytes[1], certsLengthBytes[0] });
            //每个证书的长度和证书
            var certLengthBytes = BitConverter.GetBytes(certBytes.Length);
            message.Append(new byte[] { certLengthBytes[2], certLengthBytes[1], certLengthBytes[0] });
            message.Append(certBytes);

            var handShakeType = message.Pop();
            InsertLength(message);
            message.Push(handShakeType);
            return message;
        }
    }
}
