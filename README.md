# cf-scanner

["فارسی"](/README_fa.md)

["اموزش فارسی"](/tutorial/FA.md)

Cloudflare IP scanner

## Build

To build run `go mod tidy` then `go build` in project directory

To build stripped run `go mod tidy` then `go build -ldflags "-w -s"` in project directory

## Configuration Parameters

* Hostname: The target hostname or domain to scan. For example, "sub.example.com".
* Path: The path to append to the hostname. For instance, "/test".
* Headers:
  * User-Agent: Specify the user agent for HTTP requests. In the given example, it’s set to "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0)".
  * Accept: Define the accepted content types. Here, it’s set to "*/*".
  * Accept-Language: Specify the preferred language for content. In this case, "en-US,en;q=0.5".
  * Accept-Encoding: Set the accepted encodings (e.g., "gzip", "deflate", "br", "zstd").
* ResponseHeader: Headers that an HTTP response must include.
* SNI (Server Name Indication): The SNI value to use during TLS handshake. For example, "example.com".
* Insecure: Certificate validation.
* Scheme: The protocol scheme ("http" or "https"). In this case, it’s "https".
* MaxPing: Maximum acceptable ping time (in milliseconds). Set to 150 in the provided configuration.
* Goroutines: Number of concurrent goroutines for scanning. Here, it’s set to 1.
* Scans: Total number of scans to perform. The example specifies 6000.
* Maxletency: Maximum acceptable latency (in milliseconds). Set to 500.
* Jitter: Enable calculate jitter.
* MaxJitter: Acceptable jitter.
* JitterInterval: Sleep time interval between jitter calculations in milliseconds.
* Alpn: List of supported ALPN (Application-Layer Protocol Negotiation) protocols. In this case, it’s ["http/1.1"].
* IpVersion: IP verion (v4 or v6).
* IplistPath: Path to the file containing a list of IP addresses. For instance, "ipv4.txt".
* IgnoreRange: A list of octet, where each IP matches the first octet will be ignored.
* HTTP/3: Use HTTP version 3 or not.
* Method: Scanning method. Values can be `random` or `linear`.
