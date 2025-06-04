using System;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace CheckCertificate
{
    internal class TlsClient
    {
        /// <summary>
        /// Returns true when an error occured and an error message is available.
        /// </summary>
        public bool HasError
        {
            get
            {
                return !string.IsNullOrEmpty(ErrorMessage);
            }
        }

        /// <summary>
        /// The error message in case an error has occured.
        /// </summary>
        public string ErrorMessage { get; private set; } = string.Empty;

        /// <summary>
        /// The server's certificate.
        /// </summary>
        public X509Certificate? ServerCertificate = null;

        /// <summary>
        /// Connect to the <paramref name="hostName"/> on port <paramref name="portNumber"/>. When successfull the <see cref="ServerCertificate"/>
        /// will be set. In case of a failure the <see cref="ErrorMessage"/> may contain more information.
        /// </summary>
        /// <param name="hostName"></param>
        /// <param name="portNumber"></param>
        /// <returns>Returns true when successfull, false otherwise.</returns>
        public async Task<bool> ConnectToHost(string hostName, int portNumber)
        {
            bool result = false;
            TcpClient? client = null;
            SslStream? sslStream = null;

            try
            {
                // Create a TCP connection the host
                client = new(hostName, portNumber);

                // Create an SSL stream
                sslStream = new(client.GetStream(), false, new RemoteCertificateValidationCallback(ServerCertificateValidationCallback));

                // Try to authenticate as a client without a client certificate.
                // We do this just to set up a TLS connection and get the server certificate.
                await sslStream.AuthenticateAsClientAsync(hostName, null, SslProtocols.Tls12 | SslProtocols.Tls13, true);
                ServerCertificate = sslStream.RemoteCertificate;
                result = true;
            }
            catch (AuthenticationException ex)
            {
                ErrorMessage = ex.InnerException != null ? ex.InnerException.Message : ex.Message;
                result = false;
            }
            catch (SocketException ex)
            {
                ErrorMessage = ex.Message;
                result = false;
            }
            finally
            {
                sslStream?.Close();
                client?.Close();
            }

            return result;
        }

        /// <summary>
        /// Callback for validating the server certificate.
        /// </summary>
        /// <param name="sender">The object that triggered the callback.</param>
        /// <param name="certificate">The server certificate.</param>
        /// <param name="chain">The certificate chain.</param>
        /// <param name="sslPolicyErrors">SSL policy errors</param>
        /// <returns></returns>
        private static bool ServerCertificateValidationCallback(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
        {
            // We always approve, as we want to check the certificate ourself
            return true;
        }
    }
}
