using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace CheckCertificate
{
    internal partial class CertificateChecker
    {
        /// <summary>
        /// Regular expression to extract subject name from ASN data.
        /// </summary>
        /// <returns></returns>
        [GeneratedRegex("DNS Name=(.+)", RegexOptions.IgnoreCase, "en-US")]
        private static partial Regex DNSNameRegEx();

        /// <summary>
        /// Check the certificate on the <paramref name="hostName"/> with port <paramref name="portNumber"/>.
        /// </summary>
        /// <param name="hostName">The host name.</param>
        /// <param name="portNumber">The port number.</param>
        /// <param name="warningDays">The number of days to warn before the certificate expires.</param>
        /// <param name="SkipChainValidation">Set to true to skip validation of the entire chain.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>A <see cref="ReturnValue"/> that has the result of the check.</returns>
        internal async Task<ReturnValue> Check(string hostName, int portNumber, int warningDays, bool SkipChainValidation, CancellationToken cancellationToken)
        {
            try
            {
                // Get the certificate of the host
                X509Certificate2? certificate = await GetHostCertificate(hostName, portNumber);
                if (certificate == null)
                    return ReturnValue.CertificateInvalid;

                // Check if the hostname meatches the certificate
                if (!HostnameMatchesCertificate(certificate, hostName))
                {
                    Console.Error.WriteLine($"Certificate for {hostName} on port {portNumber} does not match the host name!");
                    return ReturnValue.CertificateInvalidSubjectName;
                }

                // The current date/time
                DateTimeOffset today = DateTimeOffset.Now;

                // Check if the certificate is already valid
                if (today < certificate.NotBefore)
                {
                    Console.Error.WriteLine($"Certificate for {hostName} on port {portNumber}is not yet valid!");
                    return ReturnValue.CertificateNotValidYet;
                }

                // Check if the certificate has expired
                if (today > certificate.NotAfter)
                {
                    Console.Error.WriteLine($"Certificate for {hostName} on port {portNumber} has expired!");
                    return ReturnValue.CertificateIsExpired;
                }

                X509Chain chain = new();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EndCertificateOnly;

                // Is the certificate revoked?
                if (!chain.Build(certificate))
                {
                    Console.Error.WriteLine($"Certificate for {hostName} on port {portNumber} has been revoked!");
                    return ReturnValue.CertificateHasBeenRevoked;
                }

                // Check the entire certificate chain
                if (!SkipChainValidation)
                { 
                    // Change chain policy to entire chain
                    chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;

                    // Reset the chain
                    chain.Reset();

                    // Is the entire chain valid?
                    if (!chain.Build(certificate))
                    {
                        Console.Error.WriteLine($"Certificate chain for the certificate of {hostName} on port {portNumber} is not valid!");

                        // No, then output chain status messages
                        foreach(var chainStatus in chain.ChainStatus)
                        {
                            Console.Error.WriteLine(chainStatus.StatusInformation);
                        }

                        return ReturnValue.CertificateChainInvalid;
                    }
                }

                // Check if the certificate is almost expired
                DateTimeOffset warningDateTime = today.AddDays(warningDays);
                if (warningDateTime > certificate.NotAfter)
                {
                    // Calculate the number of days left
                    var timeLeft = certificate.NotAfter - today;
                    var daysLeft = Math.Round(timeLeft.TotalDays, MidpointRounding.AwayFromZero);

                    if (daysLeft < 2)
                    {
                        Console.Error.WriteLine($"Certificate for {hostName} on port {portNumber} expires within {timeLeft.Hours:D2}:{timeLeft.Minutes:D2} hrs!");
                    }
                    else
                    {
                        Console.Error.WriteLine($"Certificate for {hostName} on port {portNumber} expires within {daysLeft} day(s)!");
                    }

                    return ReturnValue.CertificateAlmostExpired;
                }

                // Certificate is valid
                Console.WriteLine("Certificate is valid.");
                return ReturnValue.Success;
            }
            catch (OperationCanceledException)
            {
                Console.Error.WriteLine("Execution was aborted due to pressing Ctrl-C");
                return ReturnValue.ExecutionWasAborted;
            }
        }

        /// <summary>
        /// Gets the certificate of the host.
        /// </summary>
        /// <param name="hostName">The host name</param>
        /// <param name="portNumber">The port number</param>
        /// <returns>Returns the certificate of the host if successfull, null in case of failure.</returns>
        private async Task<X509Certificate2?> GetHostCertificate(string hostName, int portNumber)
        {
            TlsClient tlsClient = new();
            if (!await tlsClient.ConnectToHost(hostName, portNumber))
            {
                Console.Error.WriteLine(tlsClient.HasError ? tlsClient.ErrorMessage : $"Unable to connect to {hostName} on port {portNumber}.");
                return null;
            }

            return new X509Certificate2(tlsClient.ServerCertificate!);
        }

        /// <summary>
        /// Check if the <paramref name="hostName"/> matches the subject name or one of the subject alternative names of the <paramref name="certificate"/>.
        /// </summary>
        /// <param name="certificate">The certificate.</param>
        /// <param name="hostName">The host name</param>
        /// <returns>True when the host name matches subject or a subject alternative name, false otherwise.</returns>
        private bool HostnameMatchesCertificate(X509Certificate2 certificate, string hostName)
        {
            bool hostnameValid;
            List<string>? subjectAlternativeNames = [];

            // Get certificate subject name
            var subjectName = certificate.GetNameInfo(X509NameType.SimpleName, false);

            // We need at least a subject name
            if (string.IsNullOrWhiteSpace(subjectName))
                return false;

            // Loop through all extensions to find the subject alternative names
            foreach (X509Extension extension in certificate.Extensions)
            {
                // Is this an alternative name extension
                if (extension.Oid?.Value != null && extension.Oid!.Value!.Equals(OidName.subjectAltName))
                {
                    // Create an AsnEncodedData object using the extension's information.
                    AsnEncodedData asndata = new(extension.Oid, extension.RawData);

                    // Parse the subject alternatice names
                    subjectAlternativeNames = ParseSubjectAltNames(asndata);
                }
            }

            // Check of the hostname matches the subject name
            if (!(hostnameValid = HostnameMatch(hostName, subjectName)))
            {
                // It doesn't, do we have subject alternative names?
                if (subjectAlternativeNames != null)
                { 
                    // So let's check the subject alternative names for a match
                    foreach (string subjectAlternativeName in subjectAlternativeNames)
                    {
                        if (hostnameValid = HostnameMatch(hostName, subjectName))
                            break;
                    }
                }
            }

            return hostnameValid;
        }


        /// <summary>
        /// Parses the <paramref name="asnData"/> to a list of subject alternative names.
        /// </summary>
        /// <param name="asnData">The encoded ASN data.</param>
        /// <returns>A list of subject alternative names if successfull. Null in case of a failure.</returns>
        private List<string>? ParseSubjectAltNames(AsnEncodedData asnData)
        {
            if (asnData == null)
                return null;

            // Split on carriage return and newline
            char[] asnSeparators = ['\r', '\n'];

            // Parse raw data into an array of strings
            string[] dnsNames = asnData.Format(true).Split(asnSeparators, StringSplitOptions.RemoveEmptyEntries);
            if (!(dnsNames.Length > 0))
                return null;

            var result = new List<string>();

            Regex regex = DNSNameRegEx();
            foreach(string dnsName in dnsNames)
            {
                // Does it match the DNS name format?
                Match match = regex.Match(dnsName);
                if (match.Success && match.Groups.Count > 1)
                {
                    // Then take group "1" as that contains the match on the dns name
                    var subjectAltName = match.Groups[1].Value;
                    if (!string.IsNullOrEmpty(subjectAltName))
                        result.Add(subjectAltName);
                }
            }

            return result;
        }

        /// <summary>
        /// Checks if the <paramref name="hostName"/> matches the <paramref name="subjectName"/>.
        /// </summary>
        /// <param name="hostName">The host name</param>
        /// <param name="subjectName">The subject name.</param>
        /// <returns></returns>
        private bool HostnameMatch(string hostName, string subjectName)
        {
            // Create a regular expression that conforms to the wild matching rules for subject names
            string wildcardMatch = string.Format("^{0}$", subjectName.Replace(".", "\\.").Replace("*", "[^.]+"));
            Regex regex = new(wildcardMatch, RegexOptions.IgnoreCase);

            return regex.IsMatch(hostName);
        }

    }
}
