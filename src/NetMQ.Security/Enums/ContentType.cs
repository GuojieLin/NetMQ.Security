namespace NetMQ.Security.TLS12
{
    /// <summary>
    /// This enum-type serves to identify the type of content -- that is,
    /// whether it is a ChangeCipherSpec , a Handshake, or just ApplicationData.
    /// </summary>
    public enum ContentType : byte
    {
        /// <summary>
        /// This signals a change of cipher-spec.
        /// </summary>
        ChangeCipherSpec = 20,
        /// <summary>
        /// Alert messages convey the severity of the message (warning or fatal) and a description of the alert
        /// </summary>
        Alert = 21,

        /// <summary>
        /// This denotes content that is of the handshaking part of the protocol.
        /// </summary>
        Handshake = 22,

        /// <summary>
        /// This denotes content that is actual application information, as opposed to part of the protocol.
        /// </summary>
        ApplicationData = 23
    }
}
