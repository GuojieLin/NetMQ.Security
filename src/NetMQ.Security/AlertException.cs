using NetMQ.Security.V0_1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NetMQ.Security
{
    public class AlertException : Exception
    {
        public NetMQMessage AlertMessage { get; private set; }

        public AlertException(NetMQMessage message , Exception innerException) 
            : base(innerException.Message, innerException)
        {
            AlertMessage = message;
        }
    }
}
