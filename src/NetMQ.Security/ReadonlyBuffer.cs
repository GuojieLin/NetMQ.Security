using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;

[assembly: InternalsVisibleTo("NetMQ.Security.Tests,PublicKey=0024000004800000940000000602000000240000525341310004000001000100c90e1ebf352af7132744cbb228ff09b10d7d758048085a392c57540a48f08321db8e92bc5605fb28a71339857b8d63752de08cb94943b292139b34616fd8a1f216a708c0bab9685e6114bf6b8d3cbba58c556fa0bc1f46970c8bd46e94c34b2c67f2220db09153f84fa0c39f5d341d84d59e3f0ccdfa033f4cfb9af501767fbb")]
namespace NetMQ.Security
{
    /// <summary>
    /// 只读缓存，为了提升性能，仅计算偏移量，减少内存拷贝
    /// |0    1   2   3   4    5    6|
    /// Offset                          Limit
    /// _Offset<_Limit
    /// </summary>
    /// <typeparam name="TEntity"></typeparam>
    public class ReadonlyBuffer<TEntity>//:ISlice<TEntity>
    {
        internal TEntity[] _Data;
        /// <summary>
        /// 相对偏移量
        /// </summary>
        public int Offset { get; protected set; }
        /// <summary>
        /// 最后一个字符,必须小于或等于_Data.Length，读取length必须小于_Limit
        /// </summary>
        public int Limit { get; protected set; }
        /// <summary>
        /// 总长度
        /// </summary>
        public int Length
        {
            get { return Limit - Offset; }
        }
        public ReadonlyBuffer(TEntity[] data) : this(data, 0, data.Length)
        {
            _Data = data;
        }
        public ReadonlyBuffer(TEntity[] data,int offset, int length)
        {
            _Data = data;
            Offset = offset;
            Limit = Offset + length;
            CheckIndexOutOfRange(offset + length - 1);
        }
        public ReadonlyBuffer(ReadonlyBuffer<TEntity> data) : this(data, data.Offset, data.Length)
        {
        }
        public ReadonlyBuffer(ReadonlyBuffer<TEntity> data, int offset, int length)
        {
            _Data = data._Data;
            Offset = offset;
            Limit = Offset + length;
            CheckIndexOutOfRange(offset + length - 1);
        }
        protected void CheckIndexOutOfRange(int index)
        {
            if (index >= this.Limit)
            {
                throw new IndexOutOfRangeException("超过最大长度" + this.Length);
            }
        }
        public ReadonlyBuffer<TEntity> Slice(int offset)
        {
            //
            //data: |0    1   2   3   4    5    6|
            //            |                     | 
            //data1:  _Offset = 1           _Limit = 5   Length = 6
            //            1   2   3   4    5
            //            0                4
            //data1.slice(1,3）
            //                |       | 
            //data2:          2   3   4    5
            return new ReadonlyBuffer<TEntity>(this, offset + this.Offset, this.Length - offset);
        }

        /// <summary>
        /// 缓冲区切片，无需复制。
        /// </summary>
        /// <param name="offset"></param>
        /// <param name="length"></param>
        /// <returns></returns>
        public ReadonlyBuffer<TEntity> Slice(int offset, int length)
        {
            CheckIndexOutOfRange(offset + this.Offset + length - 1);
            //
            //data: |0    1   2   3   4    5    6|
            //            |                     | 
            //data1:  _Offset = 1           _Limit = 5   Length = 6
            //            1   2   3   4    5
            //            0                4
            //data1.slice(1,3）
            //                |       | 
            //data2:          2   3   4    5
            return new ReadonlyBuffer<TEntity>(this, offset + this.Offset, length);
        }
        /// <summary>
        /// 偏移
        /// </summary>
        /// <param name="offset"></param>
        public void Position (int offset)
        {
            CheckIndexOutOfRange(offset - 1);
            this.Offset += offset;
        }
        public virtual TEntity Get(int index)
        {
            int position = Offset + index;
            CheckIndexOutOfRange(position);
            return this._Data[position];
        }
        /// <summary>
        /// 获取Index开始，length长度的数据，会进行内存拷贝。
        /// </summary>
        /// <param name="index"></param>
        /// <param name="length"></param>
        /// <returns></returns>
        public virtual TEntity[] Get(int index,int length)
        {
            int maxPosition = Offset + index + length - 1;
            CheckIndexOutOfRange(maxPosition);
            TEntity[] temp = new TEntity[length];
            Buffer.BlockCopy(this._Data, Offset + index, temp, 0, temp.Length);
            return temp;
        }
        ///// <summary>
        ///// 返回版本号格式如{3,3}
        ///// </summary>
        public static implicit operator TEntity[] (ReadonlyBuffer<TEntity> version)
        {
            if(version.Offset == 0 && version.Limit == version._Data.Length) return version._Data;
            //偏移量变了，需要内存拷贝。
            TEntity[] temp = new TEntity[version.Length];
            Buffer.BlockCopy(version._Data, version.Offset, temp, 0, temp.Length);
            return temp;
        }
        /// </summary>
        public static explicit operator ReadonlyBuffer<TEntity>(TEntity[] versionBuffer)
        {
            return new ReadonlyBuffer<TEntity>(versionBuffer);
        }
        public TEntity this[int index]
        {
            get { return this.Get(index); }
        }
        public TEntity[] this[int index, int length]
        {
            get { return this.Get(index, length); }
        }
    }
    public class ReadonlyByteBuffer : ReadonlyBuffer<byte>
    {
        public ReadonlyByteBuffer(byte[] data) : base(data)
        {
        }
    }
}
