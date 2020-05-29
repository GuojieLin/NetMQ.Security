using System;

namespace NetMQ.Security
{
    /// <summary>
    /// This (byte flag) enum-type represents known cipher suites
    /// that are available with SecureChannel.
    /// </summary>
    /// <remarks>
    /// TLS stands for Transport Layer Security and is the successor to Secure Sockets Layer (SSL).
    /// These are cryptographic protocols designed to provide communications security over a network.
    /// See https://www.thesprawl.org/research/tls-and-ssl-cipher-suites/ for details regarding the details of what these represent.
    /// RSA stands for Rivest, Shamir, Adleman.
    /// SHA stands for Secure Hash Algorithm.
    /// </remarks>
    [Flags]
    public enum CipherSuite 
    {

        /// <summary>
        /// The Null TLS cipher suite. This does not provide any data encryption nor data integrity function
        /// and is used during initial session establishment.
        /// </summary>
        TLS_NULL_WITH_NULL_NULL = 0,
        /// <summary>
        /// Cipher ID 2. TLS cipher with the RSA key-exchange algorithm, and SHA hashing algorithm.
        /// </summary>
        TLS_RSA_WITH_NULL_SHA = 0x02,

        /// <summary>
        /// Cipher ID 0x3B. TLS cipher with the RSA key-exchange algorithm, and SHA256 hashing algorithm.
        /// </summary>
        TLS_RSA_WITH_NULL_SHA256 = 0x3B,
        /// <summary>
        /// Cipher ID 0x2F. TLS protocol with the RSA key-exchange and authentication algorithms,
        /// the AES_128_CBC (128-bit) symmetric encryption algorithm, and SHA hashing algorithm.
        /// </summary>
        TLS_RSA_WITH_AES_128_CBC_SHA = 0x2F,

        /// <summary>
        /// Cipher ID 0x35. TLS protocol with the RSA key-exchange and authentication algorithms,
        /// the AES_256_CBC (256-bit) symmetric encryption algorithm, and SHA hashing algorithm.
        /// </summary>
        TLS_RSA_WITH_AES_256_CBC_SHA = 0x35,

        /// <summary>
        /// Cipher ID 0x3C. TLS protocol with the RSA key-exchange and authentication algorithms,
        /// the AES_128_CBC (128-bit) symmetric encryption algorithm, and SHA256 hashing algorithm.
        /// </summary>
        TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x3C,

        /// <summary>
        /// Cipher ID 0x3D. TLS protocol with the RSA key-exchange and authentication algorithms,
        /// the AES_256_CBC (256-bit) symmetric encryption algorithm, and SHA256 hashing algorithm.
        /// </summary>
        TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x3D,

        TLS_RSA_WITH_NULL_MD5 = 0x01,
        TLS_RSA_WITH_RC4_128_MD5 = 0x04,
        TLS_RSA_WITH_RC4_128_SHA = 0x05,
        TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x0A,
        TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA = 0x0D,
        TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA = 0x10,
        TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = 0x13,
        TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = 0x16,
        TLS_DH_DSS_WITH_AES_128_CBC_SHA = 0x30,
        TLS_DH_RSA_WITH_AES_128_CBC_SHA = 0x31,
        TLS_DHE_DSS_WITH_AES_128_CBC_SHA = 0x32,
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 0x33,
        TLS_DH_DSS_WITH_AES_256_CBC_SHA = 0x36,
        TLS_DH_RSA_WITH_AES_256_CBC_SHA = 0x37,
        TLS_DHE_DSS_WITH_AES_256_CBC_SHA = 0x38,
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 0x39,
        TLS_DH_DSS_WITH_AES_128_CBC_SHA256 = 0x3E,
        TLS_DH_RSA_WITH_AES_128_CBC_SHA256 = 0x3F,
        TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 = 0x40,
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = 0x67,
        TLS_DH_DSS_WITH_AES_256_CBC_SHA256 = 0x68,
        TLS_DH_RSA_WITH_AES_256_CBC_SHA256 = 0x69,
        TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 = 0x6A,
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = 0x6B,
        TLS_DH_anon_WITH_RC4_128_MD5 = 0x18,
        TLS_DH_anon_WITH_3DES_EDE_CBC_SHA = 0x1B,
        TLS_DH_anon_WITH_AES_128_CBC_SHA = 0x34,
        TLS_DH_anon_WITH_AES_256_CBC_SHA = 0x3A,
        TLS_DH_anon_WITH_AES_128_CBC_SHA256 = 0x6C,
        TLS_DH_anon_WITH_AES_256_CBC_SHA256 = 0x6D,
    }
}
