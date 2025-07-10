package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/fatih/color"
)

func downloadTest(conf *Conf, ip string) string {
	var client *http.Client
	if conf.Scheme == "https" {
		if conf.HTTP3 {
			client = h3transporter(conf)
		} else {
			tr := http.Transport{TLSClientConfig: &tls.Config{ServerName: conf.SNI, NextProtos: conf.Alpn, MinVersion: tls.VersionTLS13, InsecureSkipVerify: conf.Insecure}}
			client = &http.Client{Transport: &tr}
		}
	} else {
		client = http.DefaultClient
	}

	configUrl, configUrlErr := url.Parse(conf.DownloadTest.Url)
	if configUrlErr != nil {
		log.Fatalln(configUrlErr)
	}

	req := http.Request{Method: "GET", URL: &url.URL{Scheme: configUrl.Scheme, Host: ip, Path: configUrl.Path, RawQuery: configUrl.RawQuery}, Host: configUrl.Host}
	respone, http_err := client.Do(&req)
	if http_err != nil {
		color.Red("%s", http_err.Error())
		return "FAILED"
	}
	if respone.StatusCode != 200 {
		return "FAILED"
	}

	ch := make(chan string)
	go func() {
		buf := make([]byte, 1024*8)
		reader := respone.Body
		defer reader.Close()
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
