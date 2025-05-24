# cf-scanner

[اموزش فارسی](/tutorial/FA.md)

[English Tutorial](/tutorial/EN.md)

[Русский учебник](/tutorial/RU.md)

Cloudflare IP scanner

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

```json
{
 "Hostname": "cp.cloudflare.com", // The target hostname or domain to scan
 "Path": "/", // The path to append to the hostname
 "Headers": { // Additional HTTP headers
  "User-Agent": ["Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0)"],
  "Accept-Encoding": ["gzip", "br"]
 },
 "ResponseHeader": { // Headers that an HTTP response must include
  "Server": "cloudflare"
 },
 "SNI": "cp.cloudflare.com", // The SNI value to use during the TLS handshake
 "Insecure": false, // Certificate validation
 "Utls": { // Enable UTLS fingerprint. Supported fingerprints are firefox, edge, chrome, 360 and ios
  "Enable": true,
  "Fingerprint": "firefox"
 },
 "Scheme": "https", // The protocol scheme (http or https)
 "Ping": true, // Enable ping IP
 "MaxPing": 200, // Maximum acceptable ping time (in milliseconds)
 "Goroutines": 4, // Number of concurrent goroutines for scanning
 "Scans": 6000, // Total number of scans to perform
 "Maxlatency": 1000, // Maximum acceptable latency (in milliseconds)
 "DynamicLatency": true, // Dynamically updates MaxLatency to an average latency during runtime.
 "Jitter": true, // Enable jitter calculation
 "MaxJitter": 20, // Acceptable jitter
 "JitterInterval": 200, // Sleep time interval between jitter calculations (in milliseconds)
 "Alpn": ["http/1.1"], // List of supported ALPN (Application-Layer Protocol Negotiation) protocols
 "IpVersion": "v4", // IP version (`v4` or `v6`)
 "IplistPath": "ipv4.txt", // Path to the file containing a list of IP addresses (e.g., `ipv4.txt`)
 "IgnoreRange": ["104", "172"], // List of octets where each IP matching the first octet will be ignored
 "HTTP/3": false, // Use HTTP version 3 or not.
 "Method": "random", // Scanning method. Values can be random or linear
 "Upload": false, // Enable upload latency test
 "UploadSize": 65536, // The size of the buffer to upload,
 "Padding": true, // Enable padding in HTTP requests by adding random text as cookies. This helps eliminate fixed-size requests, enhancing security and privacy.
 "PaddingSize": "50-500" // Padding size range.
}
```
