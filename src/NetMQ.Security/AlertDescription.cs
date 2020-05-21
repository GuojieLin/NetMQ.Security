using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NetMQ.Security
{
    /// <summary>
    ///  Error handling in the TLS Handshake protocol is very simple.  
    ///  When an error is detected, the detecting party sends a message to the other party.
    ///  Upon transmission or receipt of a fatal alert message, both parties immediately close the connection.  
    ///  Servers and clients MUST forget any session-identifiers, keys, and secrets associated with a failed connection.
    ///  Thus, any connection terminated with a fatal alert MUST NOT be resumed.
    ///  
    ///  Whenever an implementation encounters a condition which is defined as a fatal alert, 
    ///  it MUST send the appropriate alert prior to closing the connection.
    ///  For all errors where an alert level is not explicitly specified, 
    ///  the sending party MAY determine at its discretion whether to treat this as a fatal error or not.
    ///  If the implementation chooses to send an alert but intends to close the connection immediately afterwards,
    ///  it MUST send that alert at the fatal alert level.
    ///  
    ///  If an alert with a level of warning is sent and received, generally the connection can continue normally.
    ///  If the receiving party decides not to proceed with the connection (e.g., after having received a no_renegotiation alert that it is not willing to accept),
    ///  it SHOULD send a fatal alert to terminate the connection.Given this, the sending party cannot, in general, know how the receiving party will behave.
    ///  Therefore, warning alerts are not very useful when the sending party wants to continue the connection, and thus are sometimes omitted.
    ///  For example, if a peer decides to accept an expired certificate (perhaps after confirming this with the user) and wants to continue the connection, 
    ///  it would not generally send a certificate_expired alert.
    /// </summary>
    public enum AlertDescription
    {
        CloseNotify = 0,
        /// <summary>
        /// An inappropriate message was received.  
        /// This alert is always fatal and should never be observed in communication between proper implementations.
        /// </summary>
        UnexpectedMessage =10,
        /// <summary>
        /// This alert is returned if a record is received with an incorrect
        ///   MAC.  This alert also MUST be returned if an alert is sent because
        /// a TLSCiphertext decrypted in an invalid way: either it wasn't an
        /// even multiple of the block length, or its padding values, when
        /// checked, weren't correct.  This message is always fatal and should
        /// never be observed in communication between proper implementations
        /// (except when messages were corrupted in the network).
        /// </summary>
        BadRecordMac = 20,
        /// <summary>
        /// This alert was used in some earlier versions of TLS, and may have
        ///   permitted certain attacks against the CBC mode [CBCATT].  It MUST
        /// NOT be sent by compliant implementations.
        /// </summary>
        RecryptionFailedReserved = 21,

        /// <summary>
        ///  A TLSCiphertext record was received that had a length more than
        /// 2^14+2048 bytes, or a record decrypted to a TLSCompressed record
        /// with more than 2^14+1024 bytes.  This message is always fatal and
        /// should never be observed in communication between proper
        /// implementations (except when messages were corrupted in the
        /// network).
        /// </summary>
        RecordOverflow = 22,
        /// <summary>
        /// The decompression function received improper input (e.g., data that would expand to excessive length).
        /// This message is always fatal and should never be observed in communication between proper implementations.
        /// </summary>
        DecompressionFailure = 30,
        /// <summary>
        /// Reception of a handshake_failure alert message indicates that 
        /// the sender was unable to negotiate an acceptable set of security parameters given the options available.  
        /// This is a fatal error.
        /// </summary>
        HandshakeFailure = 40,
        /// <summary>
        ///  This alert was used in SSLv3 but not any version of TLS.  
        ///  It MUST NOT be sent by compliant implementations.
        /// </summary>
        NoCertificateReserved = 41,
        /// <summary>
        /// A certificate was corrupt, contained signatures that did not verify correctly, etc.
        /// </summary>
        BadCertificate = 42,
        /// <summary>
        /// A certificate was of an unsupported type.
        /// </summary>
        UnsupportedCertificate = 43,
        /// <summary>
        /// A certificate was revoked by its signer.
        /// </summary>
        CertificateRevoked = 44,
        /// <summary>
        /// A certificate has expired or is not currently valid.
        /// </summary>
        CertificateExpired = 45,
        /// <summary>
        /// Some other (unspecified) issue arose in processing the certificate, rendering it unacceptable.
        /// </summary>
        CertificateUnknown = 46,
        /// <summary>
        /// A field in the handshake was out of range or inconsistent with other fields.  This message is always fatal.

        /// </summary>
        IllegalParameter = 47,
        /// <summary>
        /// A valid certificate chain or partial chain was received, 
        /// but the certificate was not accepted because the CA certificate could not be located or couldn't be matched with a known, trusted CA.  
        /// This message is always fatal.
        /// </summary>
        UnknownCa = 48,
        /// <summary>
        /// A valid certificate was received, but when access control was  applied, the sender decided not to proceed with negotiation.  
        /// This message is always fatal.
        /// </summary>
        AccessDenied = 49,
        /// <summary>
        /// A message could not be decoded because some field was out of the specified range or the length of the message was incorrect.  
        /// This message is always fatal and should never be observed in communication between proper implementations (except when messages were corrupted in the network).
        /// </summary>
        DecodeError = 50,
        /// <summary>
        ///  A handshake cryptographic operation failed, including being unable to correctly verify a signature or validate a Finished message.
        ///  This message is always fatal.
        /// </summary>
        DecryptError = 51,
        /// <summary>
        /// This alert was used in some earlier versions of TLS.  
        /// It MUST NOT be sent by compliant implementations.
        /// </summary>
        ExportEestrictionReserved = 60,
        /// <summary>
        ///  The protocol version the client has attempted to negotiate is recognized but not supported.  
        ///  (For example, old protocol versions might be avoided for security reasons.)  
        ///  This message is always fatal.
        /// </summary>
        ProtocolVersion = 70,
        /// <summary>
        /// Returned instead of handshake_failure when a negotiation has failed specifically 
        /// because the server requires ciphers more secure than those supported by the client.  
        /// This message is always fatal.
        /// </summary>
        InsufficientSecurity = 71,
        /// <summary>
        /// An internal error unrelated to the peer or 
        /// the correctness of the protocol (such as a memory allocation failure) makes it impossible to continue.  
        /// This message is always fatal.
        /// </summary>
        InternalError = 80,
        /// <summary>
        /// This handshake is being canceled for some reason unrelated to a protocol failure.  
        /// If the user cancels an operation after the handshake is complete, 
        /// just closing the connection by sending a close_notify is more appropriate.  
        /// This alert should be followed by a close_notify.  
        /// This message is generally a warning.
        /// </summary>
        UserCanceled = 90,
        /// <summary>
        /// Sent by the client in response to a hello request or by the server in response to a client hello after initial handshaking.  
        /// Either of these would normally lead to renegotiation; 
        /// when that is not appropriate, the recipient should respond with this alert.  
        /// At that point, the original requester can decide whether to proceed with the connection.  
        /// One case where this would be appropriate is where a server has spawned a process to satisfy a request; 
        /// the process might receive security parameters (key length, authentication, etc.) at startup, 
        /// and it might be difficult to communicate changes to these parameters after that point.  
        /// This message is always a warning.
        /// </summary>
        NoRenegotiation = 100,
        /// <summary>
        /// sent by clients that receive an extended server hello containing an extension that they did not put in the corresponding client hello.  
        ///     This message is always fatal.
        /// </summary>
        UnsupportedExtension = 110,
    }
}
