using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NetMQ.Security
{
    public struct TLSLength 
    {
        /// <summary>
        /// 10进制长度
        /// </summary>
        public int Length { get; set; }
        /// <summary>
        /// TLS报文占用大小
        /// </summary>
        public int Capacity { get; set; }

        public TLSLength(byte[] versionBuffer)
        {
            Capacity = versionBuffer.Length;
            byte[] temp = new byte[4];
            for (int i = 0; i < versionBuffer.Length; i++)
            {
                //倒序
                //比如 0 0 1-> 1 0 0
                temp[i] = versionBuffer[versionBuffer.Length - 1 - i];
            }
            //长度不足填充0
            for (int i = versionBuffer.Length; i < temp.Length; i++)
            {
                //填充1 0 0 -> 1 0 0 0
                temp[i] = 0;
            }
            Length = BitConverter.ToInt32(temp, 0);
        }
        public TLSLength(int length, int capacity)
        {
            Length = length;
            Capacity = capacity;
        }
        /// <summary>
        /// 返回版本号格式如{3,3}
        /// </summary>
        public static implicit operator byte[] (TLSLength tLSLength)
        {
            return BitConverter.GetBytes(tLSLength.Length).Take(tLSLength.Capacity).Reverse().ToArray();
        }
        /// </summary>
        public static explicit operator TLSLength(byte[] versionBuffer)
        {
            return new TLSLength(versionBuffer);
        }

    }
}
