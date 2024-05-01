# cf-scanner

Cloudflare IP scanner

اسکن آیپی تمیز کلودفلیر

## Build

To build run `go build` in project directory

> برای بیلد کردن پروژه در مسیر پروژه دستور `go build` را وارد کنید

To build stripped run `go build -ldflags "-w -s"` in project directory

> برای بیلد کردن پروژه بصورت استریپ در مسیر پروژه دستور `go build -ldflags "-w -s"` را وارد کنید

## Config

* Hostname: The domain used in the HTTP header and for Server Name Indication (SNI) during the TLS handshake.

> نام دامنه ای که در هدر درخواست HTTP و به عنوان SNI در TLS Handshake بکار می رود.

* Scheme: The scheme of the request, which can be either `http` or `https`.

* MaxPing: The maximum allowed ping.

> حداکثر پینگ مجاز

* Goroutines: The number of concurrent tasks (goroutines) to execute.

> تعداد وظایف همزمان (گوروتین‌ها) برای اجرا

* Scans: The number of IP addresses to be scanned per goroutine.

> تعداد آدرس‌های IP که هر گوروتین باید اسکن کند

* MaxLatency: The maximum allowed latency.

> حداکثر زمان تأخیر مجاز

* ALPN: A list of ALPN (Application-Layer Protocol Negotiation) values used during the TLS handshake.
