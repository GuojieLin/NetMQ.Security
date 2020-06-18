using NetMQ.Security.Enums;
using NetMQ.Security.TLS12;
using NetMQ.Security.TLS12.HandshakeMessages;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace NetMQ.Security.Extensions
{
    public static class ByteArrayExtensions
    {
        public static byte[] LengthToBigEndianBytes(this byte[] bytes, int length)
        {
            if (length > 4) throw new ArgumentException("max length 4 byte");
            byte[] temp = BitConverter.GetBytes(bytes.Length);
            //由于BitConverter.GetBytes是Little-Endian,因此需要转换为Big-Endian
            return temp.Take(length).Reverse().ToArray();
        }
        public static byte[] LengthToLittleEndianBytes(this byte[] bytes, int length)
        {
            if (length > 4) throw new ArgumentException("max length 4 byte");
            byte[] temp = BitConverter.GetBytes(bytes.Length);
            //由于BitConverter.GetBytes是Little-Endian,因此需要转换为Big-Endian
            return temp.Take(length).ToArray();
        }

        public static byte[] Combine(this byte[] bytes1, byte[] bytes2)
        {
            byte[] c = new byte[bytes1.Length + bytes2.Length];

            Buffer.BlockCopy(bytes1, 0, c, 0, bytes1.Length);
            Buffer.BlockCopy(bytes2, 0, c, bytes1.Length, bytes2.Length);
            return c;
        }
    }
}
