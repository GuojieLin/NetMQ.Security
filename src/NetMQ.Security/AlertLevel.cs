using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NetMQ.Security
{
    public enum AlertLevel
    {
        /// <summary>
        ///  connection or security may be unstable.
        /// </summary>
        Warning = 1,
        /// <summary>
        /// connection or security may be compromised, or an unrecoverable error has occurred.
        /// </summary>
        Fatal = 2,
    }
}
