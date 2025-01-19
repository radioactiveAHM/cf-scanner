# cf-scanner

["فارسی"](/README_fa.md)

["اموزش فارسی"](/tutorial/FA.md)

Cloudflare IP scanner

## Build

To build, run the following commands in the project directory:

```sh
go mod tidy
go build -ldflags "-w -s"
```

## Configuration Parameters

- **Hostname**: The target hostname or domain to scan (e.g., `sub.example.com`).
- **Path**: The path to append to the hostname (e.g., `/test`).
- **Headers**: HTTP headers.
- **ResponseHeader**: Headers that an HTTP response must include.
- **SNI (Server Name Indication)**: The SNI value to use during the TLS handshake (e.g., `example.com`).
- **Insecure**: Certificate validation.
- **Scheme**: The protocol scheme (`http` or `https`). In this case, it’s `https`.
- **Ping**: Enable ping IP.
- **MaxPing**: Maximum acceptable ping time (in milliseconds).
- **Goroutines**: Number of concurrent goroutines for scanning. Here, it’s set to `1`.
- **Scans**: Total number of scans to perform. The example specifies `6000`.
- **MaxLatency**: Maximum acceptable latency (in milliseconds). Set to `500`.
- **Jitter**: Enable jitter calculation.
- **MaxJitter**: Acceptable jitter.
- **JitterInterval**: Sleep time interval between jitter calculations (in milliseconds).
- **ALPN**: List of supported ALPN (Application-Layer Protocol Negotiation) protocols.
- **IPVersion**: IP version (`v4` or `v6`).
- **IPListPath**: Path to the file containing a list of IP addresses (e.g., `ipv4.txt`).
- **IgnoreRange**: A list of octets where each IP matching the first octet will be ignored.
- **HTTP/3**: Use HTTP version 3 or not.
- **Method**: Scanning method. Values can be `random` or `linear`.
- **Upload**: Enable upload latency test.
- **UploadSize**: The size of the buffer to upload.
