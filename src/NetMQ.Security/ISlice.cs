namespace NetMQ.Security
{
    public interface ISlice<TEntity, TEntityItem> where TEntity : ReadonlyBuffer<TEntityItem>
    {
        /// <summary>
        /// 相对偏移量
        /// </summary>
        int Offset { get; }
        /// <summary>
        /// 最后一个字符,必须小于或等于_Data.Length，读取length必须小于_Limit
        /// </summary>
        int Limit { get; }
        /// <summary>
        /// 总长度
        /// </summary>
        int Length { get; }
        BufferPool<TEntity, TEntityItem> Slice(int offset, int length);
    }
    public interface ISlice<TEntity> 
    {
        /// <summary>
        /// 相对偏移量
        /// </summary>
        int Offset { get; }
        /// <summary>
        /// 最后一个字符,必须小于或等于_Data.Length，读取length必须小于_Limit
        /// </summary>
        int Limit { get; }
        /// <summary>
        /// 总长度
        /// </summary>
        int Length { get; }
        ByteBufferPool Slice(int offset, int length);
    }
}