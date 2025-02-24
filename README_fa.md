# cf-scanner

اسکنر آیپی تمیز کلودفلیر

## Build

برای بیلد کردن پروژه در مسیر پروژه دستور پایین را وارد کنید

```sh
go mod tidy
go build -ldflags "-w -s"
```

## Config

HTTP = اچ-تی-تی-پی

- **Hostname**: نام میزبان یا دامنه هدف برای اسکن (`sub.example.com`).
- **Path**: مسیری که به نام میزبان اضافه می‌شود (`/test`).
- **Headers**: هدرهای اچ-تی-تی-پی.
- **ResponseHeader**: هدرهایی که یک پاسخ اچ-تی-تی-پی باید شامل شود.
- **SNI (Server Name Indication)**: نام دامنه که هنگام تی ال اس هندشیک بکار می رود. به عنوان مثال.
- **Insecure**: اعتبارسنجی گواهینامه.
- **Scheme**: طرح پروتکل (`http` یا `https`).
- **Ping**: فعال کردن پینگ IP.
- **MaxPing**: حداکثر زمان پینگ قابل قبول (به میلی‌ثانیه).
- **Goroutines**: تعداد گوروتین های همزمان برای اسکن.
- **Scans**: تعداد کل اسکن.
- **MaxLatency**: حداکثر تأخیر قابل قبول (به میلی‌ثانیه).
- **Jitter**: فعال کردن محاسبه نوسان.
- **MaxJitter**: نوسان قابل قبول.
- **JitterInterval**: فاصله زمانی خواب بین محاسبات نوسان (به میلی‌ثانیه).
- **ALPN**: ALPN.
- **IPVersion**: IP نسخه (`v4` یا `v6`).
- **IPListPath**: مسیر فایل حاوی لیست آدرس‌ها (`ipv4.txt`).
- **IgnoreRange**: لیستی از اکتت‌ها که هر آیپی مطابق با اولین اکتت نادیده گرفته می‌شود.
- **HTTP/3**: HTTP 3 فعال سازی.
- **Method**: `random` یا `linear`.
- **Upload**: فعال کردن تست تأخیر آپلود.
- **UploadSize**: اندازه بافر برای آپلود.
