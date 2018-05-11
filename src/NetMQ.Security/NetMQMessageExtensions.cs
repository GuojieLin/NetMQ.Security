using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NetMQ.Security
{
    internal static class NetMQMessageExtensions
    {
        internal static void GetLength(this NetMQMessage message, byte[] lengthBytes)
        {
            if (lengthBytes.Length > 4) throw new ArgumentException("the Byte Length must less than or equals 4");
            int length = 0;
            for (int i = 0; i < message.FrameCount; i++)
            {
                length += message[i].BufferSize;
            }
            double maxLength = Math.Pow(256, lengthBytes.Length);
            if (length > maxLength)
            {
                throw new ArgumentException("the length must less than " + maxLength);
            }

            byte[] temp = BitConverter.GetBytes(length);
            //由于BitConverter.GetBytes是Little-Endian,因此需要转换为Big-Endian
            for(int i = 0; i < lengthBytes.Length; i ++)
            {
                lengthBytes[i] = temp[lengthBytes.Length - i - 1];
            }
        }
    }
}
