using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NetMQ.Security
{
    internal class BufferPool<TEntity, TEntityItem> : ISlice<TEntity, TEntityItem> where TEntity : ReadonlyBuffer<TEntityItem>
    {
        private const int DEFAULT_CAPACITY = 10;
        public int Offset { get; protected set; }

        public int Limit { get; protected set; }
        /// <summary>
        /// 缓存长度，计算每个项的实际长度
        /// </summary>
        public int Length
        {
            get { return _Buffers.Skip(Offset).Take(Limit - Offset).Sum(b => b.Length); }
        }

        protected List<TEntity> _Buffers { get; set; }
        internal BufferPool(TEntity buffer) : this(DEFAULT_CAPACITY)
        {
            Combine(buffer);
        }
        internal BufferPool(int capacity)
        {
            _Buffers = new List<TEntity>(capacity);
        }

        public void Combine(TEntity buffer)
        {
            lock (_Buffers)
            {
                _Buffers.Add(buffer);
            }
        }
        /// <summary>
        /// 将bufferpoll分片，offset表示的是实际TEntityItem偏移量，length为长度。
        /// </summary>
        /// <param name="offset"></param>
        /// <param name="length"></param>
        /// <returns></returns>
        public BufferPool<TEntity, TEntityItem> Slice(int offset, int length)
        {
            BufferPool<TEntity, TEntityItem> pool = new BufferPool<TEntity, TEntityItem>(this._Buffers.Count);
            int position = 0;
            int sum = 0;
            foreach (TEntity entity in _Buffers)
            {
                //还没有达到偏移量，则看下一个
                if (entity.Length + position < offset)
                {
                    position += offset;
                    continue;
                }
                else
                {
                    //需要获取的
                    int count = entity.Length < length - sum ? entity.Length : length - sum;

                    ReadonlyBuffer<TEntityItem> item;
                    if (count == entity.Length)
                    {
                        //需要获取的长度和当前entity一样，则直接用当前对象
                        item = entity;
                    }
                    else
                    {
                        item = new ReadonlyBuffer<TEntityItem>(entity, 0, count);
                    }
                    pool.Combine((TEntity)item);
                    sum += count;
                }
            }
            return pool;
        }
        public static BufferPool<TEntity, TEntityItem> Create(TEntity data)
        {
            return new BufferPool<TEntity, TEntityItem>(data);
        }
    }


    internal class ByteBufferPool: BufferPool<ReadonlyBuffer<byte>,byte>
    {
        private const int DEFAULT_CAPACITY = 10;

        internal ByteBufferPool(int capacity) : base(capacity)
        {
        }
        public byte GetByte(int index)
        {
            for (int i = Offset; i < Limit; i++)
            {
                ReadonlyBuffer<byte> buffer = _Buffers[i];
                if (buffer.Length < index)
                {
                    index -= buffer.Length;
                    continue;
                }
                return buffer[index];
            }
            throw new ArgumentOutOfRangeException("index");
        }

        public void Clear()
        {
            lock (_Buffers)
            {
                _Buffers.Clear();
            }

        }
        public byte[] GetTotalBytes()
        {
            byte[] bytes = new byte[Length];
            int offset = 0;
            for (int i = 0; i < _Buffers.Count; i++)
            {
                byte[] buffer;
                lock (_Buffers)
                {
                    buffer = _Buffers[i];
                }
                System.Buffer.BlockCopy(buffer, 0, bytes, offset, buffer.Length);
                offset += buffer.Length;
            }
            return bytes;
        }


        public static implicit operator byte[] (ByteBufferPool p)
        {
            return p.GetTotalBytes();
        }
    }
}
