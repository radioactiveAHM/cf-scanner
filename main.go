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
)

type Conf struct {
	Hostname   string              `json:"Hostname"`
	Path       string              `json:"Path"`
	Headers    map[string][]string `json:"Headers"`
	SNI        string              `json:"SNI"`
	MaxPing    int                 `json:"MaxPing"`
	Goroutines int                 `json:"Goroutines"`
	Scans      int                 `json:"Scans"`
	Maxletency int64               `json:"Maxletency"`
	Jitter     bool                `json:"Jitter"`
	MaxJitter  float64             `json:"MaxJitter"`
	Scheme     string              `json:"Scheme"`
	Alpn       []string            `json:"Alpn"`
	IpVersion  string              `json:"IpVersion"`
	IplistPath string              `json:"IplistPath"`
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

	// Data from config
	hostname := conf.Hostname
	path := conf.Path
	headers := conf.Headers
	sni := conf.SNI
	maxping := conf.MaxPing
	goroutines := conf.Goroutines
	scans := conf.Scans
	var maxletency int64 = conf.Maxletency
	scheme := conf.Scheme
	alpn := conf.Alpn
	ipversion := conf.IpVersion
	iplistpath := conf.IplistPath
	cjitter := conf.Jitter
	maxjitter := conf.MaxJitter

	ch := make(chan string)
	for range goroutines {
		go func() {
			// Transporter for TLS
			tr := &http.Transport{
				TLSClientConfig: &tls.Config{ServerName: sni, NextProtos: alpn, MinVersion: tls.VersionTLS13},
			}
			// Load IP list file
			file, _ := os.ReadFile(iplistpath)
			for range scans {
				// pick an ip
				ip := ""
				if ipversion == "v4" {
					ranges := strings.Split(string(file), "\n")
					n4 := strconv.Itoa(rand.Intn(255))
					ip_parts := strings.Split(strings.TrimSpace(ranges[rand.Intn(len(ranges))]), ".")
					ip = fmt.Sprintf("%s.%s.%s.%s", ip_parts[0], ip_parts[1], ip_parts[2], n4)
				} else if ipversion == "v6" {
					ops := []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f", ""}
					n1 := rand.Intn(len(ops))
					n2 := rand.Intn(len(ops))
					n3 := rand.Intn(len(ops))
					n4 := rand.Intn(len(ops))
					ranges := strings.Split(string(file), "\n")
					selected := strings.TrimSpace(ranges[rand.Intn(len(ranges))])
					ip = "[" + selected + ops[n1] + ops[n2] + ops[n3] + ops[n4] + "]"
				} else {
					log.Fatalf("Invalid IP version")
				}

				// ping ip
				pinger, ping_err := probing.NewPinger(ip)
				pinger.SetPrivileged(true)
				pinger.Timeout = time.Duration(maxping) * time.Millisecond
				if ping_err != nil {
					log.Println(ping_err.Error())
					continue
				}
				pinger.Count = 1
				pinging_err := pinger.Run()
				if pinging_err != nil {
					log.Println(pinging_err.Error())
					continue
				}

				fmt.Printf("%s\t%s\n", ip, pinger.Statistics().MinRtt)

				if pinger.Statistics().PacketLoss > 0 || pinger.Statistics().MinRtt > (time.Duration(maxping)*time.Millisecond) {
					continue
				}

				// generate http req
				req := http.Request{Method: "GET", URL: &url.URL{Scheme: scheme, Host: ip, Path: path}, Host: hostname}
				req.Header = headers

				var client *http.Client
				if conf.Scheme == "https" {
					client = &http.Client{Transport: tr}
				} else {
					client = http.DefaultClient
				}

				client.Timeout = time.Millisecond * time.Duration(maxletency)
				s := time.Now()
				// send request
				respone, http_err := client.Do(&req)
				e := time.Now()
				latency := e.UnixMilli() - s.UnixMilli()
				if http_err != nil {
					color.Red("%s", http_err.Error())
					continue
				}

				if (respone.StatusCode == 200 || respone.StatusCode == 204) && respone.Header.Get("Server") == "cloudflare" {
					// Calc jiiter
					jitter_str := ""
					if cjitter {
						latencies := []float64{}
						for range 5 {
							s := time.Now()
							// send request
							_, http_err := client.Do(&req)
							e := time.Now()
							latency := e.UnixMilli() - s.UnixMilli()
							if http_err != nil {
								continue
							}
							latencies = append(latencies, float64(latency))
						}
						if len(latencies) == 0 {
							continue
						}
						jitter := Calc_jitter(latencies)
						if jitter > maxjitter {
							color.Yellow("%s\t%s\t%d\t%f\n", ip, pinger.Statistics().MinRtt, latency, jitter)
							continue
						}
						jitter_str = fmt.Sprintf("\t%f", jitter)
					}
					rep := fmt.Sprintf("%s\t%s\t%d\t%s\n", ip, pinger.Statistics().MinRtt, latency, jitter_str)
					color.Cyan("%s", rep)
					ch <- rep
				} else {
					fmt.Printf("%s\t%s\tHTTP.StatusCode=%d\n", ip, pinger.Statistics().MinRtt, respone.StatusCode)
				}
			}
			ch <- "end"
		}()
	}

	file, _ := os.OpenFile("result.txt", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	defer file.Close()

	deadgoroutines := 0
	for {
		if deadgoroutines == goroutines {
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
}
