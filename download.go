package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/fatih/color"
	utls "github.com/refraction-networking/utls"
)

func downloadTest(preclient *http.Client, conf *Conf, ip string, fingerprint utls.ClientHelloID) string {
	configUrl, configUrlErr := url.Parse(conf.DownloadTest.Url)
	if configUrlErr != nil {
		log.Fatalln(configUrlErr)
	}

	var client *http.Client
	if !conf.DownloadTest.SeparateConnection {
		client = preclient
	} else {
		if configUrl.Scheme == "https" {
			if conf.HTTP3 {
				client = h3transporter(conf, &conf.DownloadTest.SNI)
			} else {
				if conf.TLS.Utls.Enable {
					uclient, utlsE := utlsTransporter(conf, fingerprint, &conf.DownloadTest.SNI, ip)
					if utlsE != nil {
						return "FAILED"
					}
					client = uclient
				} else {
					client = tlsTransporter(conf, &conf.DownloadTest.SNI)
				}
			}
		} else {
			client = http.DefaultClient
		}
	}

	req := http.Request{Method: "GET", URL: &url.URL{Scheme: configUrl.Scheme, Host: ip, Path: configUrl.Path, RawQuery: configUrl.RawQuery}, Host: configUrl.Host}
	respone, http_err := client.Do(&req)
	if http_err != nil {
		color.Red("%s", http_err.Error())
		return "FAILED"
	}
	if respone.StatusCode != 200 {
		color.Red("Download host status code: %s", respone.Status)
		return "FAILED"
	}

	reader := respone.Body
	defer reader.Close()
	ch := make(chan string)
	go func() {
		buf := make([]byte, 1024*8)
		read := 0
		start := time.Now()
		for {
			if read >= conf.DownloadTest.TargetBytes {
				break
			}
			size, readErr := reader.Read(buf)
			read += size
			if readErr != nil {
				break
			}
		}
		elapsed := time.Now()

		if read < conf.DownloadTest.TargetBytes {
			ch <- "JAMMED"
		}

		latency := float32(elapsed.UnixMilli()-start.UnixMilli()) / 1000

		bytesPerSecond := float32(read) / latency
		ch <- fmt.Sprintf("%fMB/S", bytesPerSecond/1000000)
	}()

	select {
	case report := <-ch:
		return report
	case <-time.After(time.Millisecond * time.Duration(conf.DownloadTest.Timeout)):
		return "Timeout"
	}
}
