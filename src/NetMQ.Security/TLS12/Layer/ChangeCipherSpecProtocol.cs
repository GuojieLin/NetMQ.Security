using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NetMQ.Security.TLS12.Layer
{
    public class ChangeCipherSpecProtocol : RecordProtocol
    {
        public enum ChangeCipherSpec : byte
        {
            change_cipher_spec = 1
        }
        public ChangeCipherSpec Type { get; set; }
        public ChangeCipherSpecProtocol():base(false)
        {
        }
        /// <summary>
        /// <![CDATA[
        /// TLSv1.2 Record Layer: Change Cipher Spec Protocol: Change Cipher Spec
        ///      Content Type: Change Cipher Spec(20)
        ///  Version: TLS 1.2 (0x0303)
        ///  Length: 1
        ///  Change Cipher Spec Message
        /// ]]>
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public override int LoadFromByteBuffer(ReadonlyBuffer<byte> data)
        {
            Type = (ChangeCipherSpec)data[0];
            //Change Cipher Spec Message
            return 1;
        }
        public static implicit operator byte[] (ChangeCipherSpecProtocol message)
        {
            return new byte[1] { (byte)ChangeCipherSpec.change_cipher_spec };
        }
        public override byte[] ToBytes()
        {
            return this;
        }
    }
}
