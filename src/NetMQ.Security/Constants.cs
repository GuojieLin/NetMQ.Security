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
        public const int RANDOM_LENGTH = 32;
        public const int CIPHER_SUITES_LENGTH = 2;
        public const int CIPHER_SUITE_LENGTH = 2;
        public const int CLIENT_KEY_EXCHANGE_LENGTH = 3;
        public const int IV_LENGTH = 2;
        public const int SEQ_NUM_LENGTH = 8;
        public const int FRAME_COUNT_LENGTH = 4;
        public const int CONTENT_LENGTH = 2;

        public static byte[] V0_1 = new byte[2]{0,1};
        public static byte[] V0_2 = new byte[2]{0,2};
    }
}
