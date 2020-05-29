using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NetMQ.Security.Extensions
{
    public static class IntExtensions
    {
        public static byte[] ToBigEndianBytes(this int value, int length)
        {
            if (length > 4) throw new ArgumentException("max length 4 byte");
            byte[] temp = BitConverter.GetBytes(value);
            //由于BitConverter.GetBytes是Little-Endian,因此需要转换为Big-Endian
            return temp.Take(length).Reverse().ToArray();
        }
    }
}
