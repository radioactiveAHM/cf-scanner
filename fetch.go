package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
)

type Release struct {
	Assets []Asset `json:"assets"`
}

type Asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

func githubTlsTransporter(sni string) *http.Client {
	tr := http.Transport{
		TLSClientConfig: &tls.Config{ServerName: sni, NextProtos: []string{"h2", "http/1.1"}},
		Protocols:       &http.Protocols{},
	}
	tr.Protocols.SetHTTP1(true)
	tr.Protocols.SetHTTP2(true)

	return &http.Client{
		Transport: &tr,
	}
}

func GithubAPI(api string, fileName string, saveAs string) error {
	apiUrl, parseUrlErr := url.Parse(api)
	if parseUrlErr != nil {
		return parseUrlErr
	}

	client := githubTlsTransporter(apiUrl.Host)

	resp, respErr := client.Get(api)
	if respErr != nil {
		return respErr
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("response status code: %d", resp.StatusCode)
	}

	respBuffer, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return readErr
	}

	var release Release
	releaseErr := json.Unmarshal(respBuffer, &release)
	if releaseErr != nil {
		return releaseErr
	}

	for _, asset := range release.Assets {
		if asset.Name == fileName {
			browserUrl, parseUrlErr := url.Parse(asset.BrowserDownloadURL)
			if parseUrlErr != nil {
				return parseUrlErr
			}

			client := githubTlsTransporter(browserUrl.Host)

			resp, respErr := client.Get(asset.BrowserDownloadURL)
			if respErr != nil {
				return respErr
			}
			defer resp.Body.Close()

			ipv4Bytes, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				return readErr
			}

			ipv4File, ipv4FileErr := os.OpenFile(saveAs, os.O_WRONLY|os.O_CREATE, 0600)
			if ipv4FileErr != nil {
				return ipv4FileErr
			}
			ipv4File.Write(ipv4Bytes)
			ipv4File.Close()

			return nil
		}
	}

	return fmt.Errorf("failed to get ipv4.txt")

}
