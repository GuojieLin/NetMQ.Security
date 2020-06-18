using NetMQ.Security.Enums;
using NetMQ.Security.Extensions;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace NetMQ.Security.TLS12.HandshakeMessages
{
    /// <summary>
    /// The CertificateMessage is a type of HandshakeMessage with a HandshakeType of Certificate.
    /// It holds a Certificate, and overrides SetFromNetMQMessage and ToNetMQMessage to read/write the certificate
    /// from the frames of a NetMQMessage.
    /// </summary>
    internal class CertificateMessage : HandshakeMessage
    {
        /// <summary>
        /// Get the part of the handshake-protocol that this HandshakeMessage represents
        /// - in this case a Certificate.
        /// </summary>
        public override HandshakeType HandshakeType => HandshakeType.Certificate;

        /// <summary>
        /// Get or set the X.509 Digital Certificate that this message contains.
        /// </summary>
        public X509Certificate2 Certificate { get; set; }

        /// <summary>
        /// <![CDATA[
        /// Handshake Protocol: Certificate
        /// Handshake Type: Certificate(11)
        /// Length: 864
        /// Certificates Length: 861
        /// Certificates(861 bytes)
        ///     Certificate Length: 858
        ///     Certificate: 308203563082023ea003020102020900e32c1aec6d99fd28… (pkcs-9-at-emailAddress=lingj @fingard.com.cn, id-at-commonName= Dm_ca, id-at-organizationalUnitName= fg, id-at-organizationName= fg, id-at-localityName= hz, id-at-stateOrProvinceName=
        /// ]]>
        /// </summary>
        /// <param name="buffer"></param>
        public override void LoadFromByteBuffer(ReadonlyBuffer<byte> buffer)
        {
            int offset = 0;
            int certificatesLength = BitConverter.ToInt32(new byte[] { buffer[2], buffer[1], buffer[0], 0 }, 0);
            offset += Constants.CERTIFICATE_LENGTH;
            //第一个证书长度
            int certificateLength = BitConverter.ToInt32(new byte[] { buffer[5], buffer[4], buffer[3], 0 }, 0);
            offset += Constants.CERTIFICATE_LENGTH;
            byte[] certificateBytes = buffer[offset, certificateLength];

            //暂时只加载第一个证书
            Certificate = new X509Certificate2();
            Certificate.Import(certificateBytes);
            offset += certificateLength;
        }

        public override byte[] ToBytes()
        {
            return this;
        }
        public static implicit operator byte[] (CertificateMessage message)
        {
            int sum = 0;
            List<byte[]> list = new List<byte[]>(10);
            byte[] certBytes = message.Certificate.Export(X509ContentType.Cert);
            //Certificates Length:
            var certLengthBytes = (certBytes.Length + 3).ToBigEndianBytes(3);
            sum += Add(certLengthBytes, list);
            //Certificate Length:
            var certsLengthBytes = certBytes.LengthToBigEndianBytes(3);
            sum += Add(certsLengthBytes, list);
            //Certificate:
            sum += Add(certBytes, list);
            return ByteArrayListToByteArray(list, sum);
        }
    }
}
