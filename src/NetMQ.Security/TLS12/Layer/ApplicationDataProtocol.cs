using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NetMQ.Security.TLS12.Layer
{
    public class ApplicationDataProtocol : RecordProtocol
    {
        public ApplicationDataProtocol() : base(true)
        {
        }
        public static implicit operator byte[] (ApplicationDataProtocol message)
        {
            return message.HandShakeData;
        }
        public override byte[] ToBytes()
        {
            return this;
        }
    }
}
