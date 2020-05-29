using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using NetMQ.Security;
using NetMQ.Security.Enums;
using NetMQ.Security.Extensions;
using NetMQ.Security.TLS12;
using NetMQ.Security.TLS12.HandshakeMessages;
using NetMQ.Security.TLS12.Layer;
using NUnit.Framework;

namespace NetMQ.Security.Tests
{
    [TestFixture]
    public class ReadonlyBufferTests
    {
        [Test]
        public void InitTest()
        {
             ReadonlyBuffer<byte> data = new ReadonlyBuffer<byte>("00-01-02-03-04-05-06-07-08-09-0A-0B-0C-0D-0E-0F-10-11-12-13-14-15-16-17-18-19-1A-1B-1C-1D-1E-1F".ConvertHexToByteArray('-'));
            Assert.AreEqual(data.Offset, 0);
            Assert.AreEqual(data._Data.Length, 32);
            Assert.AreEqual(data.Limit, 32);
            Assert.AreEqual(data.Length, 32);
        }
        [Test]
        public void SliceTest()
        {
            ReadonlyBuffer<byte> data = new ReadonlyBuffer<byte>("00-01-02-03-04-05-06-07-08-09-0A-0B-0C-0D-0E-0F-10-11-12-13-14-15-16-17-18-19-1A-1B-1C-1D-1E-1F".ConvertHexToByteArray('-'));
            ReadonlyBuffer<byte> data2 = data.Slice(5);
            Assert.AreEqual(data2._Data, data._Data);
            Assert.AreEqual(data2.Offset, 5);
            Assert.AreEqual(data2._Data.Length, 32);
            Assert.AreEqual(data2.Limit, 32);
            Assert.AreEqual(data2.Length, 27);
            Assert.AreEqual(data2[0], (byte)5);
            Assert.AreEqual(data2[26], (byte)31);
            Assert.Throws<IndexOutOfRangeException>(() =>
            {
                var a = data2[27];
            });
        }
        [Test]
        public void Slice2Test()
        {
            ReadonlyBuffer<byte> data = new ReadonlyBuffer<byte>("00-01-02-03-04-05-06-07-08-09-0A-0B-0C-0D-0E-0F-10-11-12-13-14-15-16-17-18-19-1A-1B-1C-1D-1E-1F".ConvertHexToByteArray('-'));
            ReadonlyBuffer<byte> data2 = data.Slice(5);
            Assert.AreEqual(data2._Data, data._Data);
            ReadonlyBuffer<byte> data3 = data2.Slice(8);
            Assert.AreEqual(data3._Data, data2._Data);
            Assert.AreEqual(data3.Offset, 13);
            Assert.AreEqual(data3._Data.Length, 32);
            Assert.AreEqual(data3.Limit, 32);
            Assert.AreEqual(data3.Length, 19);
            Assert.AreEqual(data3[0], (byte)13);
            Assert.AreEqual(data3[18], (byte)31);
            Assert.Throws<IndexOutOfRangeException>(() =>
            {
                var a = data3[19];
            });
            ReadonlyBuffer<byte> data4 = data3.Slice(8,7);
            Assert.AreEqual(data4._Data, data4._Data);
            Assert.AreEqual(data4.Offset, 21);
            Assert.AreEqual(data4._Data.Length, 32);
            Assert.AreEqual(data4.Limit, 28);
            Assert.AreEqual(data4.Length, 7);
            Assert.AreEqual(data4[0], (byte)21);
            Assert.AreEqual(data4[6], (byte)27);
            Assert.Throws<IndexOutOfRangeException>(() =>
            {
                var a = data4[7];
            });
        }
        [Test]
        public void GetByteArrayTest()
        {
            ReadonlyBuffer<byte> data = new ReadonlyBuffer<byte>("00-01-02-03-04-05-06-07-08-09-0A-0B-0C-0D-0E-0F-10-11-12-13-14-15-16-17-18-19-1A-1B-1C-1D-1E-1F".ConvertHexToByteArray('-'));
            byte[] data2 = data.Get(5, 27);
            Assert.AreEqual(data2.Length, 27);
            Assert.AreEqual(data2[0], (byte)5);
            Assert.AreEqual(data2[26], (byte)31);
        }
        [Test]
        public void SpliceAndGetByteArrayTest()
        {
            ReadonlyBuffer<byte> data = new ReadonlyBuffer<byte>("00-01-02-03-04-05-06-07-08-09-0A-0B-0C-0D-0E-0F-10-11-12-13-14-15-16-17-18-19-1A-1B-1C-1D-1E-1F".ConvertHexToByteArray('-'));

            ReadonlyBuffer<byte> data2 = data.Slice(8, 20);
            Assert.AreEqual(data2._Data, data2._Data);
            Assert.AreEqual(data2.Offset, 8);
            Assert.AreEqual(data2._Data.Length, 32);
            Assert.AreEqual(data2.Limit, 28);
            Assert.AreEqual(data2.Length, 20);
            Assert.AreEqual(data2[0], (byte)8);
            Assert.AreEqual(data2[19], (byte)27);

            byte[] data3 = data2.Get(5, 13);
            Assert.AreEqual(data3.Length, 13);
            Assert.AreEqual(data3[0], (byte)13);
            Assert.AreEqual(data3[12], (byte)25);
        }
    }
}
