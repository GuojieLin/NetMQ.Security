using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NetMQ.Security
{
    internal class Constants
    {
        public const int CONTENT_TYPE_LENGTH = 1;
        public const int PROTOCOL_VERSION_LENGTH = 2;
        public const int HAND_SHAKE_LENGTH = 2;


        public const int HAND_SHAKE_TYPE = 1;
        public const int HAND_SHAKE_CONTENT_LENGTH = 3;
        public const int SESSION_ID_LENGTH = 1;
        public const int RANDOM_LENGTH = 32;
        public const int CIPHER_SUITES_LENGTH = 2;
        public const int CIPHER_SUITE_LENGTH = 2;
        public const int COMPRESSION_MENTHOD_LENGTH = 1;
        public const int COMPRESSION_MENTHOD = 1;
        public const int CLIENT_KEY_EXCHANGE_LENGTH = 3;
        public const int CERTIFICATE_LENGTH = 3;
        public const int RSA_KEY_LENGTH = 2;
        public const int EXTENSIONS_LENTGH = 2;

        public const int IV_LENGTH = 2;
        public const int SEQ_NUM_LENGTH = 8;
        public const int FRAME_COUNT_LENGTH = 4;
        public const int CONTENT_LENGTH = 2;

        /// <summary>
        /// The length (in bytes) of the following TLSPlaintext.fragment.  The length MUST NOT exceed 2^14.
        /// The record layer fragments information blocks into TLSPlaintext records carrying data in chunks of 2^14 bytes or less.
        /// The length (in bytes) of the following TLSCiphertext.fragment. The length MUST NOT exceed 2^14 + 2048.
        /// The length (in bytes) of the following TLSCompressed.fragment. The length MUST NOT exceed 2^14 + 1024.
        /// </summary>
        public const int MAX_TLS_PLAIN_TEXT_BYTE_SIZE = 18432;



        public static byte[] V0_1 = new byte[2] { 0, 1 };
        public static byte[] V3_3 = new byte[2] { 3, 3 };

        /// <summary>
        /// 服务端支持的版本,目前只支持3,3
        /// </summary>
        public static readonly List<byte[]> SupposeVersions = new List<byte[]>() { V3_3 };
        /// <summary>
        /// 0,1是NetMQ的包格式
        /// 0,2是标准的包格式
        /// </summary>
        public static readonly List<byte[]> SupposeSubVersions = new List<byte[]>() { V3_3 };
    }
}
