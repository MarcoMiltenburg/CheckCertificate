# CheckCertificate

## About

This utility checks is the TLS certificate of a remote server is still valid. It verifies the following:

- A TCP connection can be made and a successfull TLS 1.2 or 1.3 handshake can be made.
- The subject or one of the alternative subject names matches the hostname
- That the certificate's validity period is not in the future
- That the certificate's expiry date is not in the past
- 


## Usage

```
Usage:
  CheckCertificate <host> [options]

Arguments:
  <host>  The hostname to connect to.

Options:
  --port <port>                Override the port number to use. [default: 443]
  --warningdays <warningdays>  Number of days to warn before certificate expires. [default: 14]
  --skip-chain-validation      Skip checking of the entire certificate chain. [default: False]
  --version                    Show version information
  -?, -h, --help               Show help and usage information
```

It defaults to port 443 which is the default TLS port for webservers. Optionally it's possible to specify a different port to test e.g. mail servers. The server must immediately initiate a TLS handshake. The utility does not servers that upgrade the TCP connection with e.g. the STARTTLS command.

## Errorlevels

An error level indicates the result of the check:

| Errorlevel | Description |
|:----------:|-------------|
| `0`  | No errors, the cetificate is valid. |
| `1`  | Execution is aborted either due to missing or invalid command line arguments or by pressing Ctrl-C. |
| `2`  | Execution has failed due to a fatal error. |
| `3`  | Certificate is not yet valid. It's 'NotBefore' date is in the future.. |
| `4`  | Certificate is almost expired. It's 'NotAfter' date is within 'warning days' from the current date/time. |
| `5`  | Certificate has expired. It's 'NotAfter' date is earlier than the current date/time. |
| `6`  | Certificate's 'SubjectName' or 'SubjectAltName' does not match the host name. |
| `7`  | Certificate has been revoked. |
| `8`  | One or more certificates in the certificate's chain are invalid or revoked. |
| `99` | Certificate is invalid due to any other reason. |

Remember that errorlevels must be checked in reverse order as a check for a certain errorlevel also matches all errorlevels above it.

## License

[MIT](./LICENSE) © 2025 [Marco Miltenburg](https://github.com/MarcoMiltenburg)
