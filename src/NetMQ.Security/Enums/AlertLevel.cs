using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NetMQ.Security.Enums
{
    public enum AlertLevel : byte
    {
        /// <summary>
        ///  connection or security may be unstable.
        ///  If an alert with a level of warning is sent and received, generally the connection can continue normally.
        ///  If the receiving party decides not to proceed with the connection (e.g., after having received a no_renegotiation alert that it is not willing to accept),
        ///  it SHOULD send a fatal alert to terminate the connection.Given this, the sending party cannot, in general, know how the receiving party will behave.
        ///  Therefore, warning alerts are not very useful when the sending party wants to continue the connection, and thus are sometimes omitted.
        ///  For example, if a peer decides to accept an expired certificate (perhaps after confirming this with the user) and wants to continue the connection, 
        ///  it would not generally send a certificate_expired alert.
        /// </summary>
        Warning = 1,
        /// <summary>
        /// connection or security may be compromised, or an unrecoverable error has occurred.
        ///  Error handling in the TLS Handshake protocol is very simple.  
        ///  When an error is detected, the detecting party sends a message to the other party.  
        ///  Upon transmission or receipt of a fatal alert message, both parties immediately close the connection.  
        ///  Servers and clients MUST forget any session-identifiers, keys, and secrets associated with a failed connection. 
        ///  Thus, any connection terminated with a fatal alert MUST NOT be resumed.
        ///  Whenever an implementation encounters a condition which is defined as a fatal alert, it MUST send the appropriate alert prior to closing the connection.  
        ///  For all errors where an alert level is not explicitly specified, the sending party MAY determine at its discretion whether to treat this as a fatal error or not. 
        ///  If the implementation chooses to send an alert but intends to close the connection immediately afterwards, it MUST send that alert at the fatal alert level.
        ///   If an alert with a level of warning is sent and received, generally the connection can continue normally. 
        ///   If the receiving party decides not to proceed with the connection (e.g., after having received a no_renegotiation alert that it is not willing to accept), it SHOULD send a fatal alert to terminate the connection. 
        ///   Given this, the sending party cannot, in general, know how the receiving party will behave. 
        ///   Therefore, warning alerts are not very useful when the sending party wants to continue the connection, and thus are sometimes omitted.
        ///   For example, if a peer decides to accept an expired certificate (perhaps after confirming this with the user) and wants to continue the connection, it would not generally send a certificate_expired alert.
        /// </summary>
        Fatal = 2,
    }
}
