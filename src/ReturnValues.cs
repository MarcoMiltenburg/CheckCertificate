namespace CheckCertificate
{
    internal enum ReturnValue : int
    {
        /// <summary>
        /// Return value for when execution was successfull.
        /// </summary>
        Success = 0,

        /// <summary>
        /// Return value for when execution was aborted either due to missing or invalid command line arguments or by pressing Ctrl-C.
        /// </summary>
        ExecutionWasAborted = 1,

        /// <summary>
        /// Return value for when execution has failed due to a fatal error.
        /// </summary>
        ExecutionFailed = 2,

        /// <summary>
        /// Return value for when the certificate is not yet valid. It's 'NotBefore' date is in the future.
        /// </summary>
        CertificateNotValidYet = 3,

        /// <summary>
        /// Return value for when the certificate is almost expired. It's 'NotAfter' date is within 'warning days' from the current date/time.
        /// </summary>
        CertificateAlmostExpired = 4,

        /// <summary>
        /// Return value for when the certificate has expired. It's 'NotAfter' date is earlier than the current date/time.
        /// </summary>
        CertificateIsExpired = 5,

        /// <summary>
        /// Return value for when the certificate's 'SubjectName' or 'SubjectAltName' does not match the host name.
        /// </summary>
        CertificateInvalidSubjectName = 6,

        /// <summary>
        /// Return value for when the certificate has been revoked.
        /// </summary>
        CertificateHasBeenRevoked = 7,

        /// <summary>
        /// Return value for when the certificate's chain is invalid.
        /// </summary>
        CertificateChainInvalid = 8,

        /// <summary>
        /// Return value for when the certificate is invalid due to any other reason.
        /// </summary>
        CertificateInvalid = 99
    }
}
