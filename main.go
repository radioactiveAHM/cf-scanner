package main

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	probing "github.com/prometheus-community/pro-bing"
)

func main() {
	fmt.Println("start of app")
	// input
	hostname := "discord.com"
	pingtimeout := 200
	goroutines := 10
	scans := 200

	ch := make(chan string)
	for range goroutines {
		go func() {
			for range scans {
				// pick an ip
				file, _ := os.ReadFile("ipv4.txt")
				ranges := strings.Split(string(file), "\r\n")
				n4 := strconv.Itoa(rand.Intn(255))
				selected := ranges[rand.Intn(len(ranges))]
				ip := selected + n4
				fmt.Println(ip + " selected")

				// ping ip
				pinger, ping_err := probing.NewPinger(ip)
				pinger.SetPrivileged(true)
				pinger.Timeout = time.Duration(pingtimeout) * time.Millisecond
				if ping_err != nil {
					fmt.Println(ping_err.Error())
					continue
				}
				pinger.Count = 1
				pinging_err := pinger.Run()
				if pinging_err != nil {
					fmt.Println(pinging_err.Error())
					continue
				}
				fmt.Println(pinger.Statistics().AvgRtt)

				// generate http req
				req := http.Request{Method: "GET", URL: &url.URL{Scheme: "http", Host: ip, Path: "/"}, Host: hostname}
				req.Header = map[string][]string{
					"User-Agent":      {"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0)"},
					"Accept":          {"*/*"},
					"Accept-Language": {"en-US,en;q=0.5"},
					"Accept-Encoding": {"gzip", "deflate", "br", "zstd"},
				}

				// set timeout for waiting for respone to 1s
				client := http.DefaultClient
				client.Timeout = time.Second * 1
				s := time.Now()
				// send request
				respone, http_err := client.Do(&req)
				e := time.Now()
				latency := e.UnixMilli() - s.UnixMilli()
				if http_err != nil {
					fmt.Println(http_err.Error())
					continue
				}

				println(respone.StatusCode)
				if respone.StatusCode == 200 {
					ch <- fmt.Sprintf("%s %s %d\n", ip, pinger.Statistics().AvgRtt, latency)
				}
			}
			ch <- "end"
		}()
	}

	file, _ := os.OpenFile("result.txt", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
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
			fmt.Println("end of goroutine")
			continue
		}
		file.Write([]byte(v))
	}
}
