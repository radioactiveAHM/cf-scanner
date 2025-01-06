package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	probing "github.com/prometheus-community/pro-bing"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type Conf struct {
	Hostname       string              `json:"Hostname"`
	Path           string              `json:"Path"`
	Headers        map[string][]string `json:"Headers"`
	ResponseHeader map[string]string   `json:"ResponseHeader"`
	SNI            string              `json:"SNI"`
	Insecure       bool                `json:"Insecure"`
	Ping           bool                `json:"Ping"`
	MaxPing        int                 `json:"MaxPing"`
	Goroutines     int                 `json:"Goroutines"`
	Scans          int                 `json:"Scans"`
	Maxlatency     int64               `json:"Maxlatency"`
	Jitter         bool                `json:"Jitter"`
	MaxJitter      float64             `json:"MaxJitter"`
	JitterInterval int64               `json:"JitterInterval"`
	Scheme         string              `json:"Scheme"`
	Alpn           []string            `json:"Alpn"`
	IpVersion      string              `json:"IpVersion"`
	IplistPath     string              `json:"IplistPath"`
	IgnoreRange    []string            `json:"IgnoreRange"`
	HTTP3          bool                `json:"HTTP/3"`
	Method         string              `json:"Method"`
	Upload         bool                `json:"Upload"`
}

func main() {
	// load config file
	cfile, cfile_err := os.ReadFile("conf.json")
	if cfile_err != nil {
		log.Fatalln(cfile_err.Error())
	}
	conf := Conf{}
	conf_err := json.Unmarshal(cfile, &conf)
	if conf_err != nil {
		log.Fatalln(conf_err.Error())
	}

	log.Println("start of app")

	if conf.Method == "random" {
		ch := make(chan string)
		for range conf.Goroutines {
			go func() {
				// Transporter for TLS
				tr := ctls(conf.Insecure, conf.SNI, conf.Alpn)

				// Load IP list file
				file, _ := os.ReadFile(conf.IplistPath)
				ip := ""
				for range conf.Scans {
					// pick an ip
					if conf.IpVersion == "v4" {
						ranges := strings.Split(string(file), "\n")
						n4 := strconv.Itoa(rand.Intn(255))
						randomRange := ranges[rand.Intn(len(ranges))]
						if randomRange == "" || randomRange == " " || ignore(randomRange, conf.IgnoreRange) {
							continue
						}
						ip_parts := strings.Split(strings.TrimSpace(randomRange), ".")
						ip = fmt.Sprintf("%s.%s.%s.%s", ip_parts[0], ip_parts[1], ip_parts[2], n4)
					} else if conf.IpVersion == "v6" {
						ops := []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f", ""}
						ranges := strings.Split(string(file), "\n")
						randomRange := ranges[rand.Intn(len(ranges))]
						if randomRange == "" || randomRange == " " {
							continue
						}
						selected := strings.TrimSpace(randomRange)
						ip = "[" + selected + ops[rand.Intn(len(ops))] + ops[rand.Intn(len(ops))] + ops[rand.Intn(len(ops))] + ops[rand.Intn(len(ops))] + "]"
					} else {
						log.Fatalf("Invalid IP version")
					}

					minrtt := time.Millisecond
					if conf.Ping {
						// ping ip
						pinger, ping_err := probing.NewPinger(ip)
						pinger.SetPrivileged(true)
						pinger.Timeout = time.Duration(conf.MaxPing) * time.Millisecond
						if ping_err != nil {
							log.Println("PING: " + ping_err.Error())
							continue
						}
						pinger.Count = 1
						pinging_err := pinger.Run()
						if pinging_err != nil {
							log.Println("PING: " + pinging_err.Error())
							continue
						}

						if pinger.Statistics().PacketLoss > 0 || pinger.Statistics().MinRtt > (time.Duration(conf.MaxPing)*time.Millisecond) {
							color.Red("PING: %s\t%s\n", ip, pinger.Statistics().MinRtt)
							continue
						}

						minrtt = pinger.Statistics().MinRtt
					}

					// generate http req
					req := http.Request{Method: "GET", URL: &url.URL{Scheme: conf.Scheme, Host: ip, Path: conf.Path}, Host: conf.Hostname}
					req.Header = conf.Headers

					var client *http.Client
					if conf.Scheme == "https" {
						if conf.HTTP3 {
							tconf := tls.Config{ServerName: conf.SNI, NextProtos: []string{"h3"}, InsecureSkipVerify: conf.Insecure}
							qconf := quic.Config{}
							h3wraper := http3.Transport{TLSClientConfig: &tconf, QUICConfig: &qconf}
							client = &http.Client{
								Transport: &h3wraper,
							}
						} else {
							client = &http.Client{Transport: &tr}
						}
					} else {
						client = http.DefaultClient
					}

					client.Timeout = time.Millisecond * time.Duration(conf.Maxlatency)
					s := time.Now()
					// send request
					respone, http_err := client.Do(&req)
					e := time.Now()
					latency := e.UnixMilli() - s.UnixMilli()
					if http_err != nil {
						color.Red("%s", http_err.Error())
						continue
					}

					if (respone.StatusCode == 200 || respone.StatusCode == 204) && match(respone.Header, conf.ResponseHeader) {
						// Calc jiiter
						jitter_str := ""
						if conf.Jitter {
							latencies := []float64{}
							jammed := false
							for range 5 {
								s := time.Now()
								// send request
								_, http_err := client.Do(&req)
								e := time.Now()
								latency := e.UnixMilli() - s.UnixMilli()
								if http_err != nil {
									jammed = true
									break
								}
								latencies = append(latencies, float64(latency))
								if conf.JitterInterval > 0 {
									time.Sleep(time.Millisecond * time.Duration(conf.JitterInterval))
								}
							}
							if jammed {
								color.Red("%s\t%s\t%d\tJAMMED\n", ip, minrtt, latency)
								continue
							}
							jitter := Calc_jitter(latencies)
							if jitter > conf.MaxJitter {
								color.Yellow("%s\t%s\t%d\t%f\n", ip, minrtt, latency, jitter)
								continue
							}
							jitter_str = fmt.Sprintf("\t%f", jitter)
						}
						rep := fmt.Sprintf("%s\t%s\t%d\t%s\n", ip, minrtt, latency, jitter_str)
						color.Green("%s", rep)
						ch <- rep
					} else {
						color.Red("%s\t%s\tHTTP.StatusCode=%d\n", ip, minrtt, respone.StatusCode)
					}
				}
				ch <- "end"
			}()
		}

		file, _ := os.OpenFile("result.txt", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
		defer file.Close()

		deadgoroutines := 0
		for {
			if deadgoroutines == conf.Goroutines {
				break
			}
			v, ok := <-ch
			if !ok {
				break
			}
			if v == "end" {
				deadgoroutines += 1
				color.Green("end of goroutine")
				continue
			}
			file.Write([]byte(v))
		}
	} else if conf.Method == "linear" {
		res_Ch := make(chan string)
		ip_ch := make(chan string)

		// scanners
		for range conf.Goroutines {
			go func() {
				// Transporter for TLS
				tr := ctls(conf.Insecure, conf.SNI, conf.Alpn)
				for {
					ip := <-ip_ch
					// ping ip

					minrtt := time.Millisecond
					if conf.Ping {
						pinger, ping_err := probing.NewPinger(ip)
						pinger.SetPrivileged(true)
						pinger.Timeout = time.Duration(conf.MaxPing) * time.Millisecond
						if ping_err != nil {
							log.Println("PING: " + ping_err.Error())
							continue
						}
						pinger.Count = 1
						pinging_err := pinger.Run()
						if pinging_err != nil {
							log.Println("PING: " + pinging_err.Error())
							continue
						}

						if pinger.Statistics().PacketLoss > 0 || pinger.Statistics().MinRtt > (time.Duration(conf.MaxPing)*time.Millisecond) {
							color.Red("PING: %s\t%s\n", ip, pinger.Statistics().MinRtt)
							continue
						}

						minrtt = pinger.Statistics().MinRtt
					}

					// generate http req
					req := http.Request{Method: "GET", URL: &url.URL{Scheme: conf.Scheme, Host: ip, Path: conf.Path}, Host: conf.Hostname}
					req.Header = conf.Headers

					var client *http.Client
					if conf.Scheme == "https" {
						if conf.HTTP3 {
							tconf := tls.Config{ServerName: conf.SNI, NextProtos: []string{"h3"}, InsecureSkipVerify: conf.Insecure}
							qconf := quic.Config{}
							h3wraper := http3.RoundTripper{TLSClientConfig: &tconf, QUICConfig: &qconf}
							client = &http.Client{
								Transport: &h3wraper,
							}
						} else {
							client = &http.Client{Transport: &tr}
						}
					} else {
						client = http.DefaultClient
					}

					client.Timeout = time.Millisecond * time.Duration(conf.Maxlatency)
					s := time.Now()
					// send request
					respone, http_err := client.Do(&req)
					e := time.Now()
					latency := e.UnixMilli() - s.UnixMilli()
					if http_err != nil {
						color.Red("%s", http_err.Error())
						continue
					}

					if (respone.StatusCode == 200 || respone.StatusCode == 204) && match(respone.Header, conf.ResponseHeader) {
						// Calc jiiter
						jitter_str := ""
						if conf.Jitter {
							latencies := []float64{}
							jammed := false
							for range 5 {
								s := time.Now()
								// send request
								_, http_err := client.Do(&req)
								e := time.Now()
								latency := e.UnixMilli() - s.UnixMilli()
								if http_err != nil {
									jammed = true
									break
								}
								latencies = append(latencies, float64(latency))
								if conf.JitterInterval > 0 {
									time.Sleep(time.Millisecond * time.Duration(conf.JitterInterval))
								}
							}
							if jammed {
								color.Red("%s\t%s\t%d\tJAMMED\n", ip, minrtt, latency)
								continue
							}
							jitter := Calc_jitter(latencies)
							if jitter > conf.MaxJitter {
								color.Yellow("%s\t%s\t%d\t%f\n", ip, minrtt, latency, jitter)
								continue
							}
							jitter_str = fmt.Sprintf("\t%f", jitter)
						}
						rep := fmt.Sprintf("%s\t%s\t%d\t%s\n", ip, minrtt, latency, jitter_str)
						color.Green("%s", rep)
						res_Ch <- rep
					} else {
						color.Red("%s\t%s\tHTTP.StatusCode=%d\n", ip, minrtt, respone.StatusCode)
					}
				}
			}()
		}

		// result handler
		go func() {
			file, _ := os.OpenFile("result.txt", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
			defer file.Close()

			for {
				v, ok := <-res_Ch
				if !ok {
					break
				}
				file.Write([]byte(v))
			}
		}()

		file, _ := os.ReadFile(conf.IplistPath)
		for _, iprange := range strings.Split(string(file), "\n") {
			for n4 := range 256 {
				ip_ch <- strings.Replace(strings.TrimSpace(iprange), "0/24", strconv.Itoa(n4), 1)
			}
		}
	}
}

func match(headers http.Header, tomatch map[string]string) bool {
	for header, value := range tomatch {
		if headers.Get(header) == value {
			continue
		} else {
			return false
		}
	}

	return true
}

func ignore(ip string, ignoringList []string) bool {
	n1 := strings.Split(ip, ".")[0]
	for _, ig := range ignoringList {
		if n1 == ig {
			return true
		}
	}
	return false
}

func ctls(insecure bool, sni string, alpn []string) http.Transport {
	if insecure {
		return (http.Transport{TLSClientConfig: &tls.Config{ServerName: sni, NextProtos: alpn, MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}})
	}
	return (http.Transport{TLSClientConfig: &tls.Config{ServerName: sni, NextProtos: alpn, MinVersion: tls.VersionTLS13}})
}
