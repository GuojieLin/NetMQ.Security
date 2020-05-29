using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NetMQ.Security.TLS12.HandshakeMessages
{
    /// <summary>
    /// 客户端生成的32位随机数。前4位是Unix时间戳，该时间戳为1970年1月1日0点以来的秒数。不过TLS并没有强制要求校验该时间戳，因此允许定义为其他值。后面28位为一个随机数。
    /// 通过前4字节填写时间方式，有效的避免了周期性的出现一样的随机数。使得"随机"更加"随机"。
    /// 在TLS握手时，客户端和服务端需要协商数据传输时的加密密钥。为了保证加密密钥的安全性。密钥需要通过客户端和服务端一起生成。客户端和服务端都提供一个32位的随机数，通过该随机数使用基于HMAC的PRF算法生成客户端和服务端的密钥。
    /// </summary>
    public class Random
    {
        /// <summary>
        /// 通过前4字节填写时间方式，有效的避免了周期性的出现一样的随机数。使得"随机"更加"随机"。
        /// </summary>
        public int GMT_Unix_Time { get; set; }
        public byte[] RandomBytes { get; set; }

    }
}
