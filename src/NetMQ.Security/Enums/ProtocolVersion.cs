using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NetMQ.Security
{
    /// <summary>
    /// 由于 TLS（1.0、1.1、1.2 和任何未来版本）和 SSL（2.0 和 3.0）有多种版本，因此需要协商要使用的特定协议版本。 TLS 协议为版本协商提供了一个内置机制，以免因版本选择的复杂性而困扰其他协议组件。
    /// 如果客户端不支持服务器选择的版本（或不可接受），则客户端必须发送"protocol_version"警报消息并关闭连接。
    /// TLS 服务器还可以接收包含小于支持的最高版本的版本号的客户端Hello。 如果服务器希望与旧客户端协商，它将针对不大于 ClientHello.client_version 的服务器支持的最高版本进行。
    /// 例如，如果服务器支持 TLS 1.0、1.1 和 1.2，并且client_version TLS 1.0，则服务器将继续使用 TLS 1.0 ServerHello。 如果服务器仅支持（或愿意使用）大于client_version的版本，则必须发送`protocol_version`警报消息并关闭连接。
    /// </summary>
    public struct ProtocolVersion:IEquatable<ProtocolVersion>,IEqualityComparer<ProtocolVersion>
    {
        internal readonly static ProtocolVersion UN_SUPPOSE_VERSION = new ProtocolVersion() { Major = 0, Minor = 0 };

        /// <summary>
        /// TLS1.0/SSL3.0
        /// </summary>
        public readonly static ProtocolVersion TLS10 = new ProtocolVersion() { Major = 3, Minor = 1 };
        /// <summary>
        /// TLS1.1
        /// </summary>
        public readonly static ProtocolVersion TLS11 = new ProtocolVersion() { Major = 3, Minor = 2 };
        /// <summary>
        /// TLS1.2
        /// </summary>
        public readonly static ProtocolVersion TLS12 = new ProtocolVersion() { Major = 3, Minor = 3 };
        public byte Major { get; set; }
        public byte Minor { get; set; }
        /// <summary>
        /// 返回版本号格式如{3,3}
        /// </summary>
        public static implicit operator byte[] (ProtocolVersion version)
        {
            return new[] { version.Major, version.Minor };
        }
        /// </summary>
        public static explicit operator ProtocolVersion(byte[] versionBuffer)
        {
            ProtocolVersion protocolVersion = new ProtocolVersion();
            protocolVersion.Major = versionBuffer[0];
            protocolVersion.Minor = versionBuffer[1];
            return protocolVersion;
        }


        /// </summary>
        public static bool operator ==(ProtocolVersion left, ProtocolVersion right)
        {
            return left.Equals(right);
        }
        public static bool operator !=(ProtocolVersion left, ProtocolVersion right)
        {
            return !left.Equals(right);
        }
        public static bool operator >(ProtocolVersion left, ProtocolVersion right)
        {
            if (left == right) return false;
            if (left.Major > right.Major) return true;
            if(left.Major == right.Major)
            {
                if (left.Minor > right.Minor) return true;
                return false;
            }
            return false;
        }
        public static bool operator <(ProtocolVersion left, ProtocolVersion right)
        {
            if (left == right) return false;
            if (left.Major < right.Major) return true;
            if (left.Major == right.Major)
            {
                if (left.Minor < right.Minor) return true;
                return false;
            }
            return false;
        }


        public bool Equals(ProtocolVersion other)
        {
            return ((byte[])this).SequenceEqual((byte[])other);
        }

        public bool Equals(ProtocolVersion x, ProtocolVersion y)
        {
            return ((byte[])x).SequenceEqual((byte[])y);
        }

        public int GetHashCode(ProtocolVersion obj)
        {
            return this.Major.GetHashCode() ^ this.Minor.GetHashCode();
        }

    }
}
