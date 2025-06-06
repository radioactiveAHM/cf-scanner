package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"maps"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	probing "github.com/prometheus-community/pro-bing"
	"golang.org/x/net/http2"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	utls "github.com/refraction-networking/utls"
)

type UtlsConfig struct {
	Enable      bool   `json:"Enable"`
	Fingerprint string `json:"Fingerprint"`
}

type Linear struct {
	Enable bool `json:"Enable"`
	N4     int  `json:"N4"`
}

type Conf struct {
	Hostname       string              `json:"Hostname"`
	Ports          []int               `json:"Ports"`
	Path           string              `json:"Path"`
	Headers        map[string][]string `json:"Headers"`
	ResponseHeader map[string]string   `json:"ResponseHeader"`
	SNI            string              `json:"SNI"`
	Insecure       bool                `json:"Insecure"`
	Utls           UtlsConfig          `json:"Utls"`
	Ping           bool                `json:"Ping"`
	MaxPing        int                 `json:"MaxPing"`
	Goroutines     int                 `json:"Goroutines"`
	Scans          int                 `json:"Scans"`
	Maxlatency     int64               `json:"Maxlatency"`
	DynamicLatency bool                `json:"DynamicLatency"`
	Jitter         bool                `json:"Jitter"`
	MaxJitter      float64             `json:"MaxJitter"`
	JitterInterval int64               `json:"JitterInterval"`
	Scheme         string              `json:"Scheme"`
	Alpn           []string            `json:"Alpn"`
	IpVersion      string              `json:"IpVersion"`
	IplistPath     string              `json:"IplistPath"`
	IgnoreRange    []string            `json:"IgnoreRange"`
	HTTP3          bool                `json:"HTTP/3"`
	LinearScan     Linear              `json:"LinearScan"`
	Padding        bool                `json:"Padding"`
	PaddingSize    string              `json:"PaddingSize"`
	CSV            bool                `json:"CSV"`
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

	fingerprint := utls.HelloChrome_Auto
	if conf.Utls.Enable {
		fingerprint = fgen(conf.Utls.Fingerprint)
	}

	if len(conf.Ports) == 0 {
		if conf.Scheme == "https" {
			conf.Ports = append(conf.Ports, 443)
		} else {
			conf.Ports = append(conf.Ports, 80)
		}
	}

	log.Println("Starting Scanner ->")

	if !conf.LinearScan.Enable {
		ch := make(chan string)
		for range conf.Goroutines {
			go func() {
				// Transporter for TLS
				tr := http.Transport{TLSClientConfig: &tls.Config{ServerName: conf.SNI, NextProtos: conf.Alpn, MinVersion: tls.VersionTLS13, InsecureSkipVerify: conf.Insecure}}

				// Load IP list file
				file, _ := os.ReadFile(conf.IplistPath)
				ranges := strings.Split(string(file), "\n")
				localMaxlatency := conf.Maxlatency
				for range conf.Scans {
					ip := ""
					// pick an ip
					if conf.IpVersion == "v4" {
						n4 := strconv.Itoa(rand.Intn(255))
						randomRange := ranges[rand.Intn(len(ranges))]
						if randomRange == "" || randomRange == " " || ignore(randomRange, conf.IgnoreRange) {
							continue
						}
						ip_parts := strings.Split(strings.TrimSpace(randomRange), ".")
						ip = fmt.Sprintf("%s.%s.%s.%s", ip_parts[0], ip_parts[1], ip_parts[2], n4)
					} else if conf.IpVersion == "v6" {
						ops := []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f", ""}
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

						minrtt = pinger.Statistics().AvgRtt
					}

					for _, port := range conf.Ports {
						ip := fmt.Sprintf("%s:%d", ip, port)
						// generate http req
						req := http.Request{Method: "GET", URL: &url.URL{Scheme: conf.Scheme, Host: ip, Path: conf.Path}, Host: conf.Hostname}
						req.Header = maps.Clone(conf.Headers)
						req.Header.Set("Host", conf.Hostname)
						if conf.Padding {
							req.Header.Set("Cookie", genPadding(conf.PaddingSize))
						}

						var client *http.Client
						if conf.Scheme == "https" {
							if conf.HTTP3 {
								tconf := tls.Config{ServerName: conf.SNI, NextProtos: []string{"h3"}, InsecureSkipVerify: conf.Insecure}
								qconf := quic.Config{
									InitialConnectionReceiveWindow: 1024 * 8,
									InitialStreamReceiveWindow:     1024 * 8,
								}
								h3wraper := http3.Transport{TLSClientConfig: &tconf, QUICConfig: &qconf}
								client = &http.Client{
									Transport: &h3wraper,
								}
							} else {
								if conf.Utls.Enable {
									h2 := http2.Transport{
										MaxHeaderListSize: 1024 * 8,
										MaxReadFrameSize:  1024 * 16,
										DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
											dialConn, err := net.DialTimeout(network, addr, time.Millisecond*time.Duration(localMaxlatency))
											if err != nil {
												return nil, err
											}
											config := utls.Config{ServerName: conf.SNI, NextProtos: conf.Alpn, InsecureSkipVerify: conf.Insecure}
											uTlsConn := utls.UClient(dialConn, &config, fingerprint)
											handshake_e := uTlsConn.HandshakeContext(ctx)
											if handshake_e != nil {
												return nil, handshake_e
											}
											return uTlsConn, nil
										},
									}

									client = &http.Client{
										Transport: &h2,
									}
								} else {
									client = &http.Client{Transport: &tr}
								}
							}
						} else {
							client = http.DefaultClient
						}

						client.Timeout = time.Millisecond * time.Duration(localMaxlatency)
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
							if conf.DynamicLatency {
								localMaxlatency = (localMaxlatency + latency) / 2
							}
							// Calc jiiter
							jitter_str := "Null"
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
								jitter_str = fmt.Sprintf("%f", jitter)
							}
							rep := fmt.Sprintf("%s\t%s\t%d\t%s\n", ip, minrtt, latency, jitter_str)
							color.Green("%s", rep)
							if conf.CSV {
								ch <- fmt.Sprintf("%s,%s,%d,%s\n", ip, minrtt, latency, jitter_str)
							} else {
								ch <- rep
							}
						} else {
							color.Red("%s\t%s\tHTTP.StatusCode=%d\n", ip, minrtt, respone.StatusCode)
						}
					}
				}
				ch <- "end"
			}()
		}

		file := resultFile(conf.CSV)
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
	} else {
		if conf.IpVersion != "v4" {
			log.Fatalln("Linear method is only available for ipv4")
		}
		res_Ch := make(chan string)
		ip_ch := make(chan string)

		// scanners
		for range conf.Goroutines {
			go func() {
				// Transporter for TLS
				tr := http.Transport{TLSClientConfig: &tls.Config{ServerName: conf.SNI, NextProtos: conf.Alpn, MinVersion: tls.VersionTLS13, InsecureSkipVerify: conf.Insecure}}
				localMaxlatency := conf.Maxlatency
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

						minrtt = pinger.Statistics().AvgRtt
					}

					for _, port := range conf.Ports {
						ip := fmt.Sprintf("%s:%d", ip, port)
						// generate http req
						req := http.Request{Method: "GET", URL: &url.URL{Scheme: conf.Scheme, Host: ip, Path: conf.Path}, Host: conf.Hostname}
						req.Header = maps.Clone(conf.Headers)
						req.Header.Set("Host", conf.Hostname)
						if conf.Padding {
							req.Header.Set("Cookie", genPadding(conf.PaddingSize))
						}

						var client *http.Client
						if conf.Scheme == "https" {
							if conf.HTTP3 {
								tconf := tls.Config{ServerName: conf.SNI, NextProtos: []string{"h3"}, InsecureSkipVerify: conf.Insecure}
								qconf := quic.Config{
									InitialConnectionReceiveWindow: 1024 * 8,
									InitialStreamReceiveWindow:     1024 * 8,
								}
								h3wraper := http3.Transport{TLSClientConfig: &tconf, QUICConfig: &qconf}
								client = &http.Client{
									Transport: &h3wraper,
								}
							} else {
								if conf.Utls.Enable {
									h2 := http2.Transport{
										MaxHeaderListSize: 1024 * 8,
										MaxReadFrameSize:  1024 * 16,
										DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
											dialConn, err := net.DialTimeout(network, addr, time.Millisecond*time.Duration(localMaxlatency))
											if err != nil {
												return nil, err
											}

											config := utls.Config{ServerName: conf.SNI, NextProtos: conf.Alpn, InsecureSkipVerify: conf.Insecure}
											uTlsConn := utls.UClient(dialConn, &config, fingerprint)
											handshake_e := uTlsConn.HandshakeContext(ctx)
											if handshake_e != nil {
												return nil, handshake_e
											}
											return uTlsConn, nil
										},
									}

									client = &http.Client{
										Transport: &h2,
									}
								} else {
									client = &http.Client{Transport: &tr}
								}
							}
						} else {
							client = http.DefaultClient
						}

						client.Timeout = time.Millisecond * time.Duration(localMaxlatency)
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
							if conf.DynamicLatency {
								localMaxlatency = (localMaxlatency + latency) / 2
							}
							// Calc jiiter
							jitter_str := "0"
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
								jitter_str = fmt.Sprintf("%f", jitter)
							}
							rep := fmt.Sprintf("%s\t%s\t%d\t%s\n", ip, minrtt, latency, jitter_str)
							color.Green("%s", rep)
							if conf.CSV {
								res_Ch <- fmt.Sprintf("%s,%s,%d,%s\n", ip, minrtt, latency, jitter_str)
							} else {
								res_Ch <- rep
							}
						} else {
							color.Red("%s\t%s\tHTTP.StatusCode=%d\n", ip, minrtt, respone.StatusCode)
						}
					}
				}
			}()
		}

		// result handler
		go func() {
			file := resultFile(conf.CSV)
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
		for iprange := range strings.Lines(string(file)) {
			if iprange == "" || iprange == " " {
				continue
			}
			for n4 := range conf.LinearScan.N4 {
				ip_parts := strings.Split(strings.TrimSpace(iprange), ".")
				ip_ch <- fmt.Sprintf("%s.%s.%s.%d", ip_parts[0], ip_parts[1], ip_parts[2], n4)
			}
		}
		time.Sleep(time.Second * 3)
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
		ignoren1 := strings.Split(ig, ".")[0]
		if n1 == ignoren1 {
			return true
		}
	}
	return false
}

func fgen(f string) utls.ClientHelloID {
	var finger utls.ClientHelloID

	switch f {
	case "firefox":
		finger = utls.HelloFirefox_Auto
	case "edge":
		finger = utls.HelloEdge_Auto
	case "chrome":
		finger = utls.HelloChrome_Auto
	case "360":
		finger = utls.Hello360_Auto
	case "ios":
		finger = utls.HelloIOS_Auto
	default:
		log.Fatalln("Invalid fingerprint")
	}

	return finger
}

func genPadding(r string) string {
	ab := strings.Split(r, "-")
	a, a_err := strconv.Atoi(ab[0])
	if a_err != nil {
		log.Fatalln(a_err)
	}
	b, b_err := strconv.Atoi(ab[1])
	if b_err != nil {
		log.Fatalln(b_err)
	}
	randomNumber := rand.Intn(b-a+1) + a

	return strings.Repeat("X", randomNumber)
}

func resultFile(csv bool) *os.File {
	if csv {
		will_be_created := false
		_, exist := os.Stat("result.csv")
		if exist != nil {
			will_be_created = true
		}
		csv_file, err := os.OpenFile("result.csv", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			log.Fatalln(err)
		}
		if will_be_created {
			csv_file.Write([]byte("ip:port,ping,latency,jitter\n"))
		}
		return csv_file
	} else {
		file, err := os.OpenFile("result.txt", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			log.Fatalln(err)
		}
		return file
	}
}
