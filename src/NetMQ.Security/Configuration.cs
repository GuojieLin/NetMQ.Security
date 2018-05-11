using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NetMQ.Security
{
    /// <summary>
    /// 配置
    /// </summary>
    public class Configuration
    {
        /// <summary>
        /// 是否验证对方证书合法性
        /// 默认不验证
        /// </summary>
        public bool VerifyCertificate { get; set; }
        /// <summary>
        /// 标准tls都有长度的，netmq由于字节的数据格式有长度，因此把tls里面的长度都去掉了。
        /// 默认使用标准格式
        /// </summary>
        public bool StandardTLSFormat { get; set; }


        public Configuration()
        {
            StandardTLSFormat = true;
        }
    }
}
