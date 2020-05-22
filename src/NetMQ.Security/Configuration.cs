using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
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
        /// 使用的TLS版本号
        /// 默认支支持TLS12,若设置了支持多个协议，在ClientHello和ServerHello会进行协商。
        /// 作为客户端ClientHello会使用第一个支持的版本。
        /// 作为服务端ServerHello会按校验客户端的版本服务端是否支持，若不支持，则会返回小于服务端版本的最高版本。
        /// </summary>
        public ProtocolVersion[] SupposeProtocolVersions { get; set; }

        public X509Certificate2 Certificate { get; private set; }

        public Configuration()
        {
            SupposeProtocolVersions = new[] { ProtocolVersion.TLS12 };
        }
        public void LoadCert(string certificatePath, string password)
        {
            Certificate = new X509Certificate2(certificatePath, password);
        } 
    }
}
