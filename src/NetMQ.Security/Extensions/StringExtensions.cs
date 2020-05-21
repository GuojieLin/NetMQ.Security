using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NetMQ.Security.Extensions
{
    public static class StringExtensions
    {
        public static byte[] ConvertHexToByteArray(this string hexstring,char splitStr=' ')
        {
            string[] tmpary = hexstring.Trim().Split(splitStr);
            byte[] buff = new byte[tmpary.Length];
            for (int i = 0; i < buff.Length; i++)
            {
                buff[i] = Convert.ToByte(tmpary[i], 16);
            }
            return buff;
        }
        public static byte[] ConvertHexToByteArray2(this string hexstring, char splitStr = ' ')
        {
            byte[] buff = new byte[hexstring.Length/2];
            for (int i = 0; i < hexstring.Length -1 ; i+=2)
            {
                buff[i/2] = Convert.ToByte(hexstring[i].ToString()+ hexstring[i+1].ToString(), 16);
            }
            return buff;
        }
    }
}
