using NetMQ.Security.Enums;
using NetMQ.Security.Extensions;
using System;
using System.Text;

namespace NetMQ.Security.TLS12.HandshakeMessages
{
    /// <summary>
    /// Hello Request消息用于客户端与服务端重新协商握手，该消息可能由服务器在任何时刻发送。
    /// 当客户端收到了服务端的Hello Request时可以有以下4种行为。
    /// 1. 当客户端正在协商会话，可以忽略该消息。
    /// 2. 若客户端未在协商会话但不希望重新协商时，可以忽略该消息。
    /// 3. 若客户端未在协商会话但不希望重新协商时，可以发送no_renegotiation警报。
    /// 4. 若客户端希望重新协商会话，则需要发送ClientHello重新进行TLS握手。
    /// 服务端发送了HelloRequest消息，但未收到ClientHello时，可以通过致命连接警报关闭连接。若服务端发送了HelloRequest时，必须等待握手协商处理完成后才可以继续处理应用数据消息。
    ///
    /// Finished和Certificate的握手消息验证不包括该消息的hash。
    /// </summary>
    internal class HelloRequestMessage : HandshakeMessage
    {
        public override HandshakeType HandshakeType => HandshakeType.HelloRequest;
    }
    
}
