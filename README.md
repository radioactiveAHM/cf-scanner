# cf-scanner

[اموزش فارسی](/tutorial/FA.md)

[English Tutorial](/tutorial/EN.md)

[Русский учебник](/tutorial/RU.md)

Cloudflare scanner

***This scanner can be used with any CDN, provided you have the necessary requirements, such as an IP list or domain list for scanning. By default, it is configured to target Cloudflare.***

## Build

To build, run the following commands in the project directory:

```sh
go mod tidy
go build -ldflags "-w -s"
```

## Sort `result.txt` file

- Windows:
  - Powershell: `Get-Content result.txt | Sort-Object { ($_ -split '\s+')[2] } | Out-File sorted_result.txt`
  - CMD: `powershell "Get-Content result.txt | Sort-Object { ($_ -split '\s+')[2] } | Out-File sorted_result.txt"`
  - NuShell `powershell "Get-Content result.txt | Sort-Object { ($_ -split '\\s+')[2] } | Out-File sorted_result.txt"`
- Linux:
  - Bash: `sort -k3,3 -n result.txt > sorted_result.txt`

## Configuration Parameters

- NOTE❕: If both `N3` and `N4` are set to null, the IPs listed in `IplistPath` will be scanned line by line, as-is.
- NOTE❕: Both HTTP/2 and HTTP/1.1 are supported, with protocol selection based on ALPN. If ALPN is explicitly set to `"h2"`, HTTP/2 will be used—provided the server supports it. By default, ALPN is set to `"h2", "http/1.1"`, allowing HTTP/2 when available; otherwise, the connection falls back to HTTP/1.1.
- WARNING⚠️: When UTLS is enabled, ALPN is forcibly set to `"h2", "http/1.1"` and cannot be overridden via the configuration file.
- WARNING⚠️: If DownloadTest is enabled, use only one Goroutine; running multiple will yield inaccurate results.

> [!CAUTION]
> Avoid using your own domain for scanning activities, as CDN providers may interpret the traffic as DDoS or port scanning behavior and block your domain.

```json
{
 "Hostname": "cp.cloudflare.com", // The target hostname or domain to scan.
 "Ports": [], // If empty, defaults to port 443 for HTTPS and 80 for HTTP.
 "Path": "/", // The path to append to the hostname.
 "Headers": { // Additional HTTP headers.
    "User-Agent": ["Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0)"],
    "Accept-Encoding": ["gzip", "br"]
 },
 "ResponseHeader": { // Headers that an HTTP response must include.
    "Server": "cloudflare"
 },
 "ResponseStatusCode": [200, 204], // Acceptable status codes.
 "Ping": true, // Enable ping IP.
 "MaxPing": 200, // Maximum acceptable ping time (in milliseconds).
 "Goroutines": 8, // Number of concurrent goroutines for scanning.
 "Scans": 6000, // Total number of scans to perform per goroutine.
 "Maxlatency": 1000, // Maximum acceptable latency (in milliseconds).
 "Jitter": true, // Enable jitter calculation.
 "MaxJitter": 20, // Acceptable jitter.
 "JitterInterval": 200, // Sleep time interval between jitter calculations (in milliseconds).
 "IpVersion": "v4", // IP version (`v4` or `v6`).
 "IplistPath": "ipv4.txt", // Path to the file containing a list of IP addresses (e.g., `ipv4.txt`).
 "IgnoreRange": [], // List of octets where each IP matching the first octet will be ignored. (e.g., `["172", "104"]`).
 "TLS": {
   "Enable": true,
   "SNI": "cp.cloudflare.com", // The SNI value to use during the TLS handshake.
   "Insecure": false, // Certificate validation.
   "Alpn": ["h2", "http/1.1"], // List of supported ALPN (Application-Layer Protocol Negotiation) protocols.
   "Utls": {
    "Enable": true, // Enable UTLS fingerprint.
    "Fingerprint": "firefox" // Supported fingerprints are firefox, edge, chrome, 360 and ios.
   }
 },
 "HTTP/3": false, // Use HTTP version 3 or not.
 "Noise": {
    "Enable": false, // Enable UDP noise injection for HTTP/3.
    "Packet": "Meow", // Noise payload to send.
    "Sleep": 500, // Delay in milliseconds after sending noise.
    "Base64": false // Interpret 'Packet' as raw string (false) or base64-encoded bytes (true).
 },
 "LinearScan": {
    "Enable": false, // Enable linear scanning.            104.17.178.0
    "N3": null, // Max 3Th octet of IP.                            |  |
    "N4": 256 // Max 4Th octet of IP.                             N3  N4
 },
  "DomainScan": {
    "Enable": false, // Enable domain scanning.
    "DomainAsSNI": false, // Use selected domain as SNI.
    "DomainAsHost": false, // Use selected domain as Host.
    "Shuffle": true, // Shuffle domains list for random scanning.
    "SkipIPV6": true, // Skip IPv6 as result of resolving domain.
    "DomainListPath": "cloudfalare-domains.txt" // Path to the file containing a list of domains
 },
 "Padding": true, // Enable padding in HTTP requests by adding random text as cookies. This helps eliminate fixed-size requests, enhancing security and privacy.
 "PaddingSize": "5-500", // Padding size range.
 "CSV": false, // CSV format result.
 "DownloadTest": {
    "Enable": false, // Enable the download speed test.
    "Url": "https://speed.cloudflare.com/__down?bytes=10000000", // Target URL for download.
    "SNI": "cp.cloudflare.com", // The SNI value to use during the TLS handshake for DownloadTest.
    "TargetBytes": 5000000, // Expected data in bytes; if not met, report as JAMMED.
    "Timeout": 5000 // Timeout duration in milliseconds before aborting the download.
 }
}
```
