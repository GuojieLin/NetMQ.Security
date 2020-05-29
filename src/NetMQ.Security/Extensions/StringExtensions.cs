using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NetMQ.Security.Extensions
{
    public static class StringExtensions
    {
        /// <summary>
        /// 根据符号分割将hex转换为字节数组，2个字节一组
        /// </summary>
        /// <param name="hexstring"></param>
        /// <param name="splitStr"></param>
        /// <returns></returns>
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
        /// <summary>
        /// 将连续的Hex字符串转换为字节数组
        /// </summary>
        /// <param name="hexstring"></param>
        /// <returns></returns>
        public static byte[] ConvertHexToByteArray2(this string hexstring)
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
