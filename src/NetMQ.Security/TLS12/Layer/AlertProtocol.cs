using NetMQ.Security.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NetMQ.Security.TLS12.Layer
{
    /// <summary>
    /// 警报消息传达消息的严重性（警告或致命）和警报的说明。
    /// 具有致命级别的警报消息会导致立即终止连接。
    /// 若在改变密码标准协议前接收到警报消息，是明文传输的，无需解密。
    /// 握手前明文警报：|21(1)|Version(2)|Length(2)|Alert(1)|Description(1)|
    /// </summary>
    public class AlertProtocol : RecordProtocol
    {
        public AlertLevel Level { get; set; }

        public AlertDescription Description { get; set; }
        public AlertProtocol() : base(false)
        {
        }
        public AlertProtocol(bool isEncrypted) : base(isEncrypted)
        {
        }
        public override int LoadFromByteBuffer(ReadonlyBuffer<byte> data)
        {
            if (IsEncrypted)
            {
                return base.LoadFromByteBuffer(data);
            }
            else
            {
                Level = (AlertLevel)data[0];
                Description = (AlertDescription)data[1];
                return 2;
            }
        }
        public static implicit operator byte[] (AlertProtocol message)
        {
            if (message.IsEncrypted)
            {
                return message.HandShakeData;
            }
            return new byte[] { (byte)message.Level, (byte)message.Description };
        }
        public override byte[] ToBytes()
        {
            return this;
        }
    }
}
