using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NetMQ.Security
{
    public enum AlertDescription
    {
        CloseNotify = 0,
        UnexpectedMessage =10,
        BadRecordMac = 20,
        RecryptionFailedReserved = 21,
        RecordOverflow = 22,
        DecompressionFailure = 30,
        HandshakeFailure = 40,
        NoCertificateReserved = 41,
        BadCertificate = 42,
        UnsupportedCertificate = 43,
        CertificateCevoked = 44,
        CertificateCxpired = 45,
        CertificateCnknown = 46,
        IllegalParameter = 47,
        UnknownCa = 48,
        AccessDenied = 49,
        DecodeError = 50,
        DecryptError = 51,
        ExportEestrictionReserved = 60,
        ProtocolVersion = 70,
        InsufficientSecurity = 71,
        InternalError = 80,
        UserCanceled = 90,
        NoRenegotiation = 100,
        UnsupportedExtension = 110,
    }
}
