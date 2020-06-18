using NetMQ.Security.TLS12;
using NetMQ.Security.TLS12.Layer;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NetMQ.Security
{
    public class AlertException : Exception
    {
        public AlertProtocol AlertProtocol { get; private set; }

        public AlertException(AlertProtocol alert, Exception innerException) 
            : base(innerException.Message, innerException)
        {
            AlertProtocol = alert;
        }
    }
}
