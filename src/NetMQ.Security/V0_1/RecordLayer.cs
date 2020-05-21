using NetMQ.Security.Extensions;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace NetMQ.Security.V0_1
{
    /// <summary>
    /// The RecordLayer class represents the "Record Layer" within the SSL/TLS protocol layers.
    /// This is underneath the Handshake Layer, and above the Transport Layer.
    /// </summary>
    /// <remarks>
    /// See http://technet.microsoft.com/en-us/library/cc781476(v=ws.10).aspx
    /// </remarks>
    internal class RecordLayer : IDisposable
    {
        private const string KeyExpansion = "key expansion";

        public const int WindowSize = 1024;

        private SymmetricAlgorithm m_decryptionBulkAlgorithm;
        private SymmetricAlgorithm m_encryptionBulkAlgorithm;

        private HMAC m_decryptionHMAC;
        private HMAC m_encryptionHMAC;
        /// <summary>
        /// Each connection state contains a sequence number, which is maintained separately for read and write states.
        /// The sequence number MUST be set to zero whenever a connection state is made theactive state.  
        /// Sequence numbers are of type uint64 and may not exceed 2^64-1.  
        /// Sequence numbers do not wrap.  
        /// If a TLSimplementation would need to wrap a sequence number, it must renegotiate instead.  
        /// A sequence number is incremented after each record: specifically, the first record transmitted under a particular connection state MUST use sequence number 0.
        /// The master_secret is hashed with the ClientHello.random and ServerHello.random to produce unique data encryption keys and MAC secrets for each connection.
        /// Outgoing data is protected with a MAC before transmission.
        /// To prevent message replay or modification attacks, the MAC is computed from the MAC key, the sequence number, the message length, the
        /// message contents, and two fixed character strings.  
        /// The message type field is necessary to ensure that messages intended for one TLS record layer client are not redirected to another.
        /// The sequence number ensures that attempts to delete or reorder messages will be detected.
        /// Since sequence numbers are 64 bits long, they should never overflow.Messages from one party cannot be inserted into the other's output, since they use independent MAC keys.  
        /// Similarly, the server write and client write keys are independent, so stream cipher keys are used only once. 
        /// If an attacker does break an encryption key, all messages encrypted with it can be read.Similarly, compromise of a MAC key can make message - modification attacks possible.Because MACs are also encrypted, message - alteration attacks generally require breaking the encryption algorithm as well as the MAC.
        /// Note: MAC keys may be larger than encryption keys, so messages can remain tamper resistant even if encryption keys are broken.
        /// </summary>
        private ulong m_readSequenceNumber = 0;
        private ulong m_writeSequenceNumber = 0;
        private object m_readLock = new object();
        private object m_writeLock = new object();

        private byte[] m_SubProtocolVersion;
        private ulong m_leftWindow = 0;
        private ulong m_rightWindow = WindowSize - 1;
        private readonly bool[] m_windowMap = new bool[WindowSize];
        /// <summary>
        /// 配置
        /// </summary>
        /// <summary>
        /// Create a new RecordLayer object with the given protocol-version.
        /// </summary>
        /// <param name="protocolVersion">a 2-element byte-array that denotes the version of this protocol</param>
        public RecordLayer()
        {
            SecurityParameters = new SecurityParameters
            {
                BulkCipherAlgorithm = BulkCipherAlgorithm.Null,
                MACAlgorithm = MACAlgorithm.Null
            };

            PRF = new SHA256PRF();
        }

        public SecurityParameters SecurityParameters { get; set; }

        public IPRF PRF { get; set; }

        private void GenerateKeys(
          out byte[] clientMAC, out byte[] serverMAC,
          out byte[] clientEncryptionKey, out byte[] serverEncryptionKey)
        {
            //The master secret is expanded into a sequence of secure bytes, which is then split to a client write MAC key, a server write MAC key, a   client write encryption key, and a server write encryption key.
            //Each of these is generated from the byte sequence in that order.  
            //Unused values are empty.  Some AEAD ciphers may additionally require a client write IV and a server write IV(see Section 6.2.3.3).
            byte[] seed = new byte[HandshakeLayer.RandomNumberLength * 2];

            Buffer.BlockCopy(SecurityParameters.ServerRandom, 0, seed, 0, HandshakeLayer.RandomNumberLength);
            Buffer.BlockCopy(SecurityParameters.ClientRandom, 0, seed,
              HandshakeLayer.RandomNumberLength, HandshakeLayer.RandomNumberLength);

            int length = (SecurityParameters.FixedIVLength +
                          SecurityParameters.EncKeyLength + SecurityParameters.MACKeyLength) * 2;

            if (length > 0)
            {
                byte[] keyBlock = PRF.Get(SecurityParameters.MasterSecret,
                                                           KeyExpansion, seed, length);

                clientMAC = new byte[SecurityParameters.MACKeyLength];
                Buffer.BlockCopy(keyBlock, 0, clientMAC, 0, SecurityParameters.MACKeyLength);
                int pos = SecurityParameters.MACKeyLength;

                serverMAC = new byte[SecurityParameters.MACKeyLength];
                Buffer.BlockCopy(keyBlock, pos, serverMAC, 0, SecurityParameters.MACKeyLength);
                pos += SecurityParameters.MACKeyLength;

                clientEncryptionKey = new byte[SecurityParameters.EncKeyLength];
                Buffer.BlockCopy(keyBlock, pos, clientEncryptionKey, 0, SecurityParameters.EncKeyLength);
                pos += SecurityParameters.EncKeyLength;

                serverEncryptionKey = new byte[SecurityParameters.EncKeyLength];
                Buffer.BlockCopy(keyBlock, pos, serverEncryptionKey, 0, SecurityParameters.EncKeyLength);
            }
            else
            {
                clientMAC = serverMAC = clientEncryptionKey = serverEncryptionKey = null;
            }
        }

        public void InitalizeCipherSuite()
        {
            byte[] clientMAC;
            byte[] serverMAC;
            byte[] clientEncryptionKey;
            byte[] serverEncryptionKey;

            GenerateKeys(out clientMAC, out serverMAC, out clientEncryptionKey, out serverEncryptionKey);

#if DEBUG
            Debug.WriteLine("[client mac key]:" + BitConverter.ToString(clientMAC));
            Debug.WriteLine("[server mac key]:" + BitConverter.ToString(serverMAC));
            Debug.WriteLine("[client encrypt key]:" + BitConverter.ToString(clientEncryptionKey));
            Debug.WriteLine("[server encrypt key]:" + BitConverter.ToString(serverEncryptionKey));
#endif
            if (SecurityParameters.BulkCipherAlgorithm == BulkCipherAlgorithm.AES)
            {
                m_decryptionBulkAlgorithm = new AesCryptoServiceProvider
                {
                    Padding = PaddingMode.None,
                    KeySize = SecurityParameters.EncKeyLength*8,
                    BlockSize = SecurityParameters.BlockLength*8
                };

                m_encryptionBulkAlgorithm = new AesCryptoServiceProvider
                {
                    Padding = PaddingMode.None,
                    KeySize = SecurityParameters.EncKeyLength*8,
                    BlockSize = SecurityParameters.BlockLength*8
                };

                if (SecurityParameters.Entity == ConnectionEnd.Client)
                {
                    m_encryptionBulkAlgorithm.Key = clientEncryptionKey;
                    m_decryptionBulkAlgorithm.Key = serverEncryptionKey;
                }
                else
                {
                    m_decryptionBulkAlgorithm.Key = clientEncryptionKey;
                    m_encryptionBulkAlgorithm.Key = serverEncryptionKey;
                }
            }
            else
            {
                m_decryptionBulkAlgorithm = m_encryptionBulkAlgorithm = null;
            }

            if (SecurityParameters.MACAlgorithm == MACAlgorithm.HMACSha1)
            {
                if (SecurityParameters.Entity == ConnectionEnd.Client)
                {
                    m_encryptionHMAC = new HMACSHA1(clientMAC);
                    m_decryptionHMAC = new HMACSHA1(serverMAC);
                }
                else
                {
                    m_encryptionHMAC = new HMACSHA1(serverMAC);
                    m_decryptionHMAC = new HMACSHA1(clientMAC);
                }
            }
            else if (SecurityParameters.MACAlgorithm == MACAlgorithm.HMACSha256)
            {
                if (SecurityParameters.Entity == ConnectionEnd.Client)
                {
                    m_encryptionHMAC = new HMACSHA256(clientMAC);
                    m_decryptionHMAC = new HMACSHA256(serverMAC);
                }
                else
                {
                    m_encryptionHMAC = new HMACSHA256(serverMAC);
                    m_decryptionHMAC = new HMACSHA256(clientMAC);
                }
            }
            else
            {
                m_encryptionHMAC = m_decryptionHMAC = null;
            }
        }

        /// <param name="contentType">This identifies the type of content: ChangeCipherSpec, Handshake, or ApplicationData.</param>
        /// <param name="plainMessage">The unencrypted form of the message to be encrypted.</param>
        public byte[] EncryptMessage(ContentType contentType, byte[] plainBytes)
        {
            if (SecurityParameters.BulkCipherAlgorithm == BulkCipherAlgorithm.Null &&
              SecurityParameters.MACAlgorithm == MACAlgorithm.Null)
            {
                return plainBytes;
            }
            ulong seqNum = GetAndIncreaseWriteSequneceNumber();
            //CBC块加密
            //struct {
            //    opaque IV[SecurityParameters.record_iv_length];
            //    block-ciphered struct {
            //        opaque content[TLSCompressed.length];
            //        opaque MAC[SecurityParameters.mac_length];
            //        uint8 padding[GenericBlockCipher.padding_length];
            //        uint8 padding_length;
            //    };
            //} GenericBlockCipher;
            using (var encryptor = m_encryptionBulkAlgorithm.CreateEncryptor())
            {
                byte[] seqNumBytes = BitConverter.GetBytes(seqNum);
                //在密码学的领域里，初始向量（英语：initialization vector，缩写为IV），或译初向量，又称初始变量（starting variable，缩写为SV）[1]，是一个固定长度的输入值。一般的使用上会要求它是随机数或拟随机数（pseudorandom）。使用随机数产生的初始向量才能达到语义安全（消息验证码也可能用到初始向量），并让攻击者难以对原文一致且使用同一把密钥生成的密文进行破解。在区块加密中，使用了初始向量的加密模式被称为区块加密模式。 
                //有些密码运算只要求初始向量不要重复，并只要求它用是内部求出的随机数值（这类随机数实际上不够乱）。在这类应用下，初始向量通常被称为nonce（临时使用的数值），是可控制的（stateful）而不是随机数。这种作法是因为初始向量不会被寄送到密文的接收方，而是收发两方透过事前约定的机制自行计算出对应的初始向量（不过，实现上还是经常会把nonce送过去以便检查消息的遗漏）。计数器模式中使用序列的方式来作为初始向量，它就是一种可控制之初始向量的加密模式。 
                byte[] iv = GenerateIV(encryptor, seqNumBytes);

#if DEBUG
                Debug.WriteLine("[iv]:" + BitConverter.ToString(iv));
#endif
                byte[] cipherBytes = EncryptBytes(encryptor, contentType, seqNum, plainBytes);

                byte[] genericBlockCipher = new byte[iv.Length + cipherBytes.Length];
                Buffer.BlockCopy(iv, 0, genericBlockCipher, 0, iv.Length);
                Buffer.BlockCopy(cipherBytes, 0, genericBlockCipher, iv.Length, cipherBytes.Length);
#if DEBUG
                Debug.WriteLine("[TLSCiphertext]:" + BitConverter.ToString(genericBlockCipher));
#endif
                return genericBlockCipher;

            }
        }

        /// <summary>
        /// Create and return an Initialization Vector (IV) using a given sequence-number and encryptor.
        /// </summary>
        /// <param name="encryptor">the ICryptoTransform to use to do the encryption</param>
        /// <param name="seqNumBytes">a byte-array that is the sequence-number</param>
        /// <returns>a byte-array that comprises the Initialization Vector (IV)</returns>
        private byte[] GenerateIV(ICryptoTransform encryptor, byte[] seqNumBytes)
        {
            // generating an IV by encrypting the sequence number with the random IV and encrypting symmetric key
            byte[] iv = new byte[SecurityParameters.RecordIVLength];
            Buffer.BlockCopy(seqNumBytes, 0, iv, 0, 8);

            byte padding = (byte)((encryptor.OutputBlockSize - (9 % encryptor.OutputBlockSize)) % encryptor.OutputBlockSize);
            for (int i = 8; i < iv.Length; i++)
            {
                iv[i] = padding;
            }

            // Compute the hash value for the region of the input byte-array (iv), starting at index 0,
            // and copy the resulting hash value back into the same byte-array.
            encryptor.TransformBlock(iv, 0, iv.Length, iv, 0);
            return iv;
        }

        /// <summary>
        /// Increment and return the sequence-number.
        /// </summary>
        internal ulong GetAndIncreaseReadSequneceNumber()
        {
            lock (m_readLock)
            {
                return m_readSequenceNumber++;
            }
        }
        internal ulong GetAndIncreaseWriteSequneceNumber()
        {
            lock (m_writeLock)
            {
                return m_writeSequenceNumber++;
            }
        }

        private byte[] EncryptBytes(ICryptoTransform encryptor, ContentType contentType, ulong seqNum, byte[] plainBytes)
        {
            byte[] mac;
            //记录有效负载保护
            //加密和 MAC 功能将 TLS 压缩结构转换为 TLSCipher 文本。 解密功能反转该过程。 
            //记录的 MAC 还包括一个序列号，以便可检测到缺失、额外或重复的消息。
            //  struct {
            //       ContentType type;
            //        ProtocolVersion version;
            //        uint16 length;
            //        opaque fragment[TLSPlaintext.length];
            //    }
            //    TLSPlaintext;
            if (SecurityParameters.MACAlgorithm != MACAlgorithm.Null)
            {
                byte[] versionAndType = new[] { (byte)contentType, m_SubProtocolVersion[0], m_SubProtocolVersion[1] };
                byte[] seqNumBytes = BitConverter.GetBytes(seqNum).Reverse().ToArray();//大端
                byte[] messageSize = BitConverter.GetBytes((ushort)plainBytes.Length).Take(2).Reverse().ToArray();//长度2字节

                m_encryptionHMAC.Initialize();
                m_encryptionHMAC.TransformBlock(seqNumBytes, 0, seqNumBytes.Length, seqNumBytes, 0);
                m_encryptionHMAC.TransformBlock(versionAndType, 0, versionAndType.Length, versionAndType, 0);
                m_encryptionHMAC.TransformBlock(messageSize, 0, messageSize.Length, messageSize, 0);
                m_encryptionHMAC.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
                mac = m_encryptionHMAC.Hash;
            }
            else
            {
                mac = EmptyArray<byte>.Instance;
            }

            int length = plainBytes.Length + SecurityParameters.MACLength;
            byte padding = 0;

            if (SecurityParameters.BulkCipherAlgorithm != BulkCipherAlgorithm.Null)
            {
                padding = (byte)((encryptor.OutputBlockSize -
                                        (plainBytes.Length + SecurityParameters.MACLength + 1) % encryptor.OutputBlockSize) %
                                       encryptor.OutputBlockSize);

                length += padding + 1;
            }

            byte[] cipherBytes = new byte[length];

            Buffer.BlockCopy(plainBytes, 0, cipherBytes, 0, plainBytes.Length);
            Buffer.BlockCopy(mac, 0, cipherBytes, plainBytes.Length, SecurityParameters.MACLength);
#if DEBUG
            Debug.WriteLine("[TLSPlaintext]:" + BitConverter.ToString(cipherBytes));
            Debug.WriteLine("[TLSPlaintext.data]:" + BitConverter.ToString(plainBytes));
            Debug.WriteLine("[TLSPlaintext.mac]:" + BitConverter.ToString(mac));
            Debug.WriteLine("[TLSPlaintext.padding]:" + padding);
#endif
            if (SecurityParameters.BulkCipherAlgorithm != BulkCipherAlgorithm.Null)
            {
                for (int i = plainBytes.Length + SecurityParameters.MACLength; i < cipherBytes.Length; i++)
                {
                    cipherBytes[i] = padding;
                }

                encryptor.TransformBlock(cipherBytes, 0, cipherBytes.Length, cipherBytes, 0);
            }
            return cipherBytes;
        }

        /// <summary>
        /// Return a new <see cref="NetMQMessage"/> that contains the decrypted content of the give message.
        /// </summary>
        /// <param name="contentType">This identifies the type of content: ChangeCipherSpec, Handshake, or ApplicationData.</param>
        /// <param name="cipherMessage">the message to decrypt</param>
        /// <returns>a new NetMQMessage with the contents decrypted</returns>
        /// <exception cref="NetMQSecurityException"><see cref="NetMQSecurityErrorCode.InvalidFramesCount"/>: Cipher message must have at least 2 frames, iv and sequence number.</exception>
        /// <exception cref="NetMQSecurityException"><see cref="NetMQSecurityErrorCode.ReplayAttack"/>: Message already handled or very old message, might be under replay attack.</exception>
        /// <exception cref="NetMQSecurityException"><see cref="NetMQSecurityErrorCode.EncryptedFramesMissing"/>: Frames were removed from the encrypted message.</exception>
        public NetMQMessage DecryptMessage(ContentType contentType, NetMQMessage cipherMessage)
        {
            NetMQMessage message = new NetMQMessage();
            byte[] bytes = DecryptMessage(contentType,cipherMessage.Last.Buffer);
            message.Append(bytes);
            return message;
        }
        public byte[] DecryptMessage(ContentType contentType, byte[] cipherMessage)
        {
            if (SecurityParameters.BulkCipherAlgorithm == BulkCipherAlgorithm.Null &&
              SecurityParameters.MACAlgorithm == MACAlgorithm.Null)
            {
                return cipherMessage;
            }
            //从第一个加密块开始计算
            ulong seqNum = GetAndIncreaseReadSequneceNumber();
            if (cipherMessage.Length < SecurityParameters.RecordIVLength)
            {
                throw new NetMQSecurityException(NetMQSecurityErrorCode.EncryptedFrameInvalidLength, "IV size not enough");
            }
            byte[] ivBytes = new byte[SecurityParameters.RecordIVLength];
            Buffer.BlockCopy(cipherMessage, 0, ivBytes, 0, ivBytes.Length);
            byte[] cipherBytes = new byte[cipherMessage.Length - SecurityParameters.RecordIVLength];
            Buffer.BlockCopy(cipherMessage, ivBytes.Length, cipherBytes, 0, cipherBytes.Length);


#if DEBUG
            Debug.WriteLine("[iv]:" + BitConverter.ToString(ivBytes));
#endif
            using (var decryptor = m_decryptionBulkAlgorithm.CreateDecryptor(m_decryptionBulkAlgorithm.Key, ivBytes))
            {
                byte[] padding;
                byte[] data;
                byte[] mac;

                DecryptBytes(decryptor, cipherBytes, out data, out mac, out padding);
                ValidateBytes(contentType, seqNum, data, mac, padding);
                return data;
            }
        }

        /// <exception cref="NetMQSecurityException"><see cref="NetMQSecurityErrorCode.EncryptedFrameInvalidLength"/>: The block size must be valid.</exception>
        private void DecryptBytes(ICryptoTransform decryptor, byte[] cipherBytes,
          out byte[] plainBytes, out byte[] mac, out byte[] padding)
        {
#if DEBUG
            Debug.WriteLine("[TLSCiphertext]:" + BitConverter.ToString(cipherBytes));
#endif
            if (cipherBytes.Length % decryptor.InputBlockSize != 0)
            {
                throw new NetMQSecurityException(NetMQSecurityErrorCode.EncryptedFrameInvalidLength, "Invalid block size for cipher bytes");
            }

            byte[] frameBytes = new byte[cipherBytes.Length];

            int dataLength;
            int paddingSize;

            if (SecurityParameters.BulkCipherAlgorithm != BulkCipherAlgorithm.Null)
            {
                //using (MemoryStream memoryStream = new MemoryStream(cipherBytes))
                //{
                //    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                //    {
                //        // Read the decrypted bytes from the decrypting stream
                //        // and place them in a string.
                //        cryptoStream.Read(frameBytes, 0, frameBytes.Length);
                //    }
                //}
                decryptor.TransformBlock(cipherBytes, 0, cipherBytes.Length, frameBytes, 0);
#if DEBUG
                Debug.WriteLine("[TLSPlaintext]:" + BitConverter.ToString(cipherBytes));
#endif
                paddingSize = frameBytes[frameBytes.Length - 1] + 1;

                if (paddingSize > decryptor.InputBlockSize)
                {
                    // somebody tamper the message, we don't want throw the exception yet because
                    // of timing issue, we need to throw the exception after the mac check,
                    // therefore we will change the padding size to the size of the block
                    paddingSize = decryptor.InputBlockSize;
                }

                dataLength = frameBytes.Length - paddingSize - SecurityParameters.MACLength;

                // data length can be zero if somebody tamper with the padding
                if (dataLength < 0)
                {
                    dataLength = 0;
                }
            }
            else
            {
                dataLength = frameBytes.Length - SecurityParameters.MACLength;
                frameBytes = cipherBytes;
                paddingSize = 0;
            }

            plainBytes = new byte[dataLength];
            Buffer.BlockCopy(frameBytes, 0, plainBytes, 0, dataLength);

            mac = new byte[SecurityParameters.MACLength];
            Buffer.BlockCopy(frameBytes, dataLength, mac, 0, SecurityParameters.MACLength);

            padding = new byte[paddingSize];
            Buffer.BlockCopy(frameBytes, dataLength + SecurityParameters.MACLength, padding, 0, paddingSize);
#if DEBUG
            Debug.WriteLine("[TLSPlaintext.data]:" + BitConverter.ToString(plainBytes));
            Debug.WriteLine("[TLSPlaintext.mac]:" + BitConverter.ToString(mac));
            Debug.WriteLine("[TLSPlaintext.padding]:" + paddingSize);
#endif
        }

        /// <summary>
        /// Check the given arguments and throw a <see cref="NetMQSecurityException"/> if something is amiss.
        /// </summary>
        /// <param name="contentType">This identifies the type of content: ChangeCipherSpec, Handshake, or ApplicationData.</param>
        /// <param name="seqNum"></param>
        /// <param name="frameIndex"></param>
        /// <param name="plainBytes"></param>
        /// <param name="mac"></param>
        /// <param name="padding"></param>
        /// <exception cref="NetMQSecurityException"><see cref="NetMQSecurityErrorCode.MACNotMatched"/>: MAC does not match message.</exception>
        public void ValidateBytes(ContentType contentType, ulong seqNum, byte[] plainBytes, byte[] mac, byte[] padding)
        {
            if (SecurityParameters.MACAlgorithm != MACAlgorithm.Null)
            {
                byte[] typeAndVersion = new[] { (byte)contentType, m_SubProtocolVersion[0], m_SubProtocolVersion[1] };
                byte[] seqNumBytes = BitConverter.GetBytes(seqNum).Reverse().ToArray();
                byte[] messageSize = BitConverter.GetBytes(plainBytes.Length).Take(2).Reverse().ToArray();
                //byte[] messageSize = plainBytes.LengthToBytes(2);
                m_decryptionHMAC.Initialize();
                m_decryptionHMAC.TransformBlock(seqNumBytes, 0, seqNumBytes.Length, seqNumBytes, 0);
                m_decryptionHMAC.TransformBlock(typeAndVersion, 0, typeAndVersion.Length, typeAndVersion, 0);
                m_decryptionHMAC.TransformBlock(messageSize, 0, messageSize.Length, messageSize, 0);
                m_decryptionHMAC.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
                //MAC(MAC_write_key, seq_num +
                //      TLSCompressed.type +
                //      TLSCompressed.version +
                //      TLSCompressed.length +
                //      TLSCompressed.fragment);
                //where "+" denotes concatenation.
                if (!m_decryptionHMAC.Hash.SequenceEqual(mac))
                {
                    throw new NetMQSecurityException(NetMQSecurityErrorCode.MACNotMatched, "MAC does not match message");
                }

                for (int i = 0; i < padding.Length; i++)
                {
                    if (padding[i] != padding.Length - 1)
                    {
                        throw new NetMQSecurityException(NetMQSecurityErrorCode.MACNotMatched, "MAC not matched message");
                    }
                }
            }
        }

        private bool CheckReplayAttack(ulong seqNumber)
        {
            if (seqNumber < m_leftWindow)
            {
                return true;
            }
            else if (seqNumber <= m_rightWindow)
            {
                int index = (int)(seqNumber % WindowSize);

                if (!m_windowMap[index])
                {
                    m_windowMap[index] = true;
                    return false;
                }
                else
                {
                    return true;
                }
            }
            else
            {
                // if new seq is much higher than the window size somebody is trying to do a reply attack as well
                if (seqNumber - m_rightWindow > WindowSize - 1)
                {
                    return true;
                }

                // need to extend window size
                ulong bytesToExtend = seqNumber - m_rightWindow;

                // set to false the new extension
                for (ulong i = 0; i < bytesToExtend; i++)
                {
                    int index = (int)((m_leftWindow + i) % WindowSize);

                    m_windowMap[index] = false;
                }

                m_leftWindow = m_leftWindow + bytesToExtend;
                m_rightWindow = seqNumber;

                return false;
            }
        }
        internal void SetSubProtocolVersion(byte[] subprotocolVersion)
        {
            m_SubProtocolVersion = subprotocolVersion;
        }

        /// <summary>
        /// Dispose of all contained resources.
        /// </summary>
        public void Dispose()
        {
            if (m_decryptionBulkAlgorithm != null)
            {
#if NET40
                m_decryptionBulkAlgorithm.Dispose();
#else
                m_decryptionBulkAlgorithm.Clear();
#endif
                m_decryptionBulkAlgorithm = null;
            }

            if (m_encryptionBulkAlgorithm != null)
            {
#if NET40
                m_encryptionBulkAlgorithm.Dispose();
#else
                m_encryptionBulkAlgorithm.Clear();
#endif
                m_encryptionBulkAlgorithm = null;
            }

            if (m_decryptionHMAC != null)
            {
#if NET40
                m_decryptionHMAC.Dispose();
#else
                m_decryptionHMAC.Clear();
#endif
                m_decryptionHMAC = null;
            }

            if (m_encryptionHMAC != null)
            {
#if NET40
                m_encryptionHMAC.Dispose();
#else
                m_encryptionHMAC.Clear();
#endif
                m_encryptionHMAC = null;
            }

            if (PRF != null)
            {
                PRF.Dispose();
                PRF = null;
            }
        }
    }
}
