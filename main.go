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
	"slices"
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

type Linear struct {
	Enable bool `json:"Enable"`
	N3     int  `json:"N3"`
	N4     int  `json:"N4"`
}

type DS struct {
	Enable         bool   `json:"Enable"`
	DomainAsSNI    bool   `json:"DomainAsSNI"`
	DomainAsHost   bool   `json:"DomainAsHost"`
	SkipIPV6       bool   `json:"SkipIPV6"`
	Shuffle        bool   `json:"Shuffle"`
	DomainListPath string `json:"DomainListPath"`
}

type NoiseConfig struct {
	Enable bool   `json:"Enable"`
	Packet string `json:"Packet"`
	Sleep  int    `json:"Sleep"`
}

type DownloadConfig struct {
	Enable      bool   `json:"Enable"`
	Url         string `json:"Url"`
	SNI         string `json:"SNI"`
	TargetBytes int    `json:"TargetBytes"`
	Timeout     int    `json:"Timeout"`
}

type UtlsConfig struct {
	Enable      bool   `json:"Enable"`
	Fingerprint string `json:"Fingerprint"`
}

type TLSConfig struct {
	Enable   bool       `json:"Enable"`
	SNI      string     `json:"SNI"`
	Insecure bool       `json:"Insecure"`
	Alpn     []string   `json:"Alpn"`
	Utls     UtlsConfig `json:"Utls"`
}

type UdpPayload struct {
	Payload string `json:"Payload"`
	Sleep   int    `json:"Sleep"`
}

type UdpScanConfig struct {
	Enable  bool         `json:"Enable"`
	Packets []UdpPayload `json:"Packets"`
}

type Conf struct {
	Hostname           string              `json:"Hostname"`
	Ports              []int               `json:"Ports"`
	Path               string              `json:"Path"`
	Headers            map[string][]string `json:"Headers"`
	ResponseHeader     map[string]string   `json:"ResponseHeader"`
	ResponseStatusCode []int               `json:"ResponseStatusCode"`
	Ping               bool                `json:"Ping"`
	MaxPing            int                 `json:"MaxPing"`
	Goroutines         int                 `json:"Goroutines"`
	Scans              int                 `json:"Scans"`
	Maxlatency         int64               `json:"Maxlatency"`
	Jitter             bool                `json:"Jitter"`
	MaxJitter          float64             `json:"MaxJitter"`
	JitterInterval     int64               `json:"JitterInterval"`
	IpVersion          string              `json:"IpVersion"`
	IplistPath         string              `json:"IplistPath"`
	IgnoreRange        []string            `json:"IgnoreRange"`
	TLS                TLSConfig           `json:"TLS"`
	HTTP3              bool                `json:"HTTP/3"`
	Noise              NoiseConfig         `json:"Noise"`
	LinearScan         Linear              `json:"LinearScan"`
	DomainScan         DS                  `json:"DomainScan"`
	Padding            bool                `json:"Padding"`
	PaddingSize        string              `json:"PaddingSize"`
	CSV                bool                `json:"CSV"`
	DownloadTest       DownloadConfig      `json:"DownloadTest"`
	UdpScan            UdpScanConfig       `json:"UdpScan"`
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

	if conf.UdpScan.Enable {
		color.Blue("UdpScan Scanner ->\n")
		UdpScan(&conf)
		return
	}

	fingerprint := utls.HelloChrome_Auto
	if conf.TLS.Utls.Enable {
		fingerprint = fgen(conf.TLS.Utls.Fingerprint)
	}

	scheme := "http"
	if len(conf.Ports) == 0 {
		if conf.TLS.Enable {
			scheme = "https"
			conf.Ports = append(conf.Ports, 443)
		} else {
			conf.Ports = append(conf.Ports, 80)
		}
	}

	color.Green("Starting Scanner ->\n")
	if !conf.DomainScan.Enable {
		if !conf.LinearScan.Enable {
			ch := make(chan string, conf.Goroutines)
			for range conf.Goroutines {
				go func() {
					// Load IP list file
					file, ipListFileErr := os.ReadFile(conf.IplistPath)
					if ipListFileErr != nil {
						log.Fatalln(ipListFileErr)
					}
					ranges := strings.Split(string(file), "\n")
					var client *http.Client
					if conf.TLS.Enable {
						if conf.HTTP3 {
							client = h3transporter(&conf, nil)
						} else {
							client = tlsTransporter(&conf, nil)
						}
					} else {
						client = http.DefaultClient
					}
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
							log.Fatalln("Invalid IP version")
						}

						minrtt := time.Millisecond
						if conf.Ping {
							// ping ip
							pinger, ping_err := probing.NewPinger(ip)
							pinger.SetPrivileged(true)
							pinger.Timeout = time.Duration(conf.MaxPing) * time.Millisecond
							if ping_err != nil {
								color.Red("PING: %s", ping_err)
								continue
							}
							pinger.Count = 1
							pinging_err := pinger.Run()
							if pinging_err != nil {
								color.Red("PING: %s", pinging_err)
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
							req := http.Request{Method: "GET", URL: &url.URL{Scheme: scheme, Host: ip, Path: conf.Path}, Host: conf.Hostname}
							req.Header = maps.Clone(conf.Headers)
							req.Header.Set("Host", conf.Hostname)
							if conf.Padding {
								req.Header.Set("Cookie", genPadding(conf.PaddingSize))
							}

							client.Timeout = time.Millisecond * time.Duration(conf.Maxlatency)
							s := time.Now()
							if conf.TLS.Utls.Enable && conf.TLS.Enable && !conf.HTTP3 {
								uclient, utlsE := utlsTransporter(&conf, fingerprint, nil, ip)
								if utlsE != nil {
									color.Red("%s", utlsE.Error())
									continue
								}
								client = uclient
							}
							// send request
							respone, http_err := client.Do(&req)
							e := time.Now()
							latency := e.UnixMilli() - s.UnixMilli()
							if http_err != nil {
								color.Red("%s", http_err.Error())
								continue
							}

							if slices.Contains(conf.ResponseStatusCode, respone.StatusCode) && match(respone.Header, conf.ResponseHeader) {
								// Calc jiiter
								jitter_str := "Null"
								download_test := "Null"
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
								if conf.DownloadTest.Enable {
									download_test = downloadTest(client, &conf, ip, fingerprint)
								}
								rep := fmt.Sprintf("%s\t%s\t%d\t%s\t%s\n", ip, minrtt, latency, jitter_str, download_test)
								color.Green("%s", rep)
								if conf.CSV {
									ch <- fmt.Sprintf("%s,%s,%d,%s,%s\n", ip, minrtt, latency, jitter_str, download_test)
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
			res_Ch := make(chan string, conf.Goroutines)
			ip_ch := make(chan string, conf.Goroutines)

			// scanners
			for range conf.Goroutines {
				go func() {
					var client *http.Client
					if conf.TLS.Enable {
						if conf.HTTP3 {
							client = h3transporter(&conf, nil)
						} else {
							client = tlsTransporter(&conf, nil)
						}
					} else {
						client = http.DefaultClient
					}

					for {
						ip := <-ip_ch
						// ping ip

						minrtt := time.Millisecond
						if conf.Ping {
							pinger, ping_err := probing.NewPinger(ip)
							pinger.SetPrivileged(true)
							pinger.Timeout = time.Duration(conf.MaxPing) * time.Millisecond
							if ping_err != nil {
								color.Red("PING: %s", ping_err)
								continue
							}
							pinger.Count = 1
							pinging_err := pinger.Run()
							if pinging_err != nil {
								color.Red("PING: %s", pinging_err)
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
							req := http.Request{Method: "GET", URL: &url.URL{Scheme: scheme, Host: ip, Path: conf.Path}, Host: conf.Hostname}
							req.Header = maps.Clone(conf.Headers)
							req.Header.Set("Host", conf.Hostname)
							if conf.Padding {
								req.Header.Set("Cookie", genPadding(conf.PaddingSize))
							}

							client.Timeout = time.Millisecond * time.Duration(conf.Maxlatency)
							s := time.Now()
							if conf.TLS.Utls.Enable && conf.TLS.Enable && !conf.HTTP3 {
								uclient, utlsE := utlsTransporter(&conf, fingerprint, nil, ip)
								if utlsE != nil {
									color.Red("%s", utlsE.Error())
									continue
								}
								client = uclient
							}
							// send request
							respone, http_err := client.Do(&req)
							e := time.Now()
							latency := e.UnixMilli() - s.UnixMilli()
							if http_err != nil {
								color.Red("%s", http_err.Error())
								continue
							}

							if slices.Contains(conf.ResponseStatusCode, respone.StatusCode) && match(respone.Header, conf.ResponseHeader) {
								// Calc jiiter
								jitter_str := "Null"
								download_test := "Null"
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
								if conf.DownloadTest.Enable {
									download_test = downloadTest(client, &conf, ip, fingerprint)
								}
								rep := fmt.Sprintf("%s\t%s\t%d\t%s\t%s\n", ip, minrtt, latency, jitter_str, download_test)
								color.Green("%s", rep)
								if conf.CSV {
									res_Ch <- fmt.Sprintf("%s,%s,%d,%s,%s\n", ip, minrtt, latency, jitter_str, download_test)
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
				if conf.LinearScan.N3 > 0 {
					// With N3
					for n3 := range conf.LinearScan.N3 {
						for n4 := range conf.LinearScan.N4 {
							ip_parts := strings.Split(strings.TrimSpace(iprange), ".")
							ip_ch <- fmt.Sprintf("%s.%s.%d.%d", ip_parts[0], ip_parts[1], n3, n4)
						}
					}
				} else {
					if conf.LinearScan.N4 == 0 {
						ip_ch <- strings.TrimSpace(iprange)
					} else {
						for n4 := range conf.LinearScan.N4 {
							ip_parts := strings.Split(strings.TrimSpace(iprange), ".")
							ip_ch <- fmt.Sprintf("%s.%s.%s.%d", ip_parts[0], ip_parts[1], ip_parts[2], n4)
						}
					}
				}
			}
			time.Sleep(time.Second * 3)
		}
	} else {
		// Domain Scan
		domainListFile, domainListFileErr := os.ReadFile(conf.DomainScan.DomainListPath)
		if domainListFileErr != nil {
			log.Fatalln(domainListFileErr)
		}

		domains := strings.Split(string(domainListFile), "\n")
		if conf.DomainScan.Shuffle {
			rand.Shuffle(len(domains), func(i, j int) {
				domains[i], domains[j] = domains[j], domains[i]
			})
		}

		ch := make(chan string, conf.Goroutines)
		for domainsChunk := range slices.Chunk(domains, len(domains)/conf.Goroutines) {
			go func() {
				for _, domain := range domainsChunk {
					domain := strings.TrimSpace(domain)
					ips, resolve_err := net.LookupIP(domain)
					if resolve_err != nil {
						log.Println(resolve_err)
						continue
					}

					for _, ip := range ips {
						if conf.DomainScan.SkipIPV6 {
							if ip.To4() == nil && ip.To16() != nil {
								continue
							}
						}

						minrtt := time.Millisecond
						if conf.Ping {
							// ping ip
							pinger, ping_err := probing.NewPinger(ip.String())
							pinger.SetPrivileged(true)
							pinger.Timeout = time.Duration(conf.MaxPing) * time.Millisecond
							if ping_err != nil {
								color.Red("PING: %s", ping_err)
								continue
							}
							pinger.Count = 1
							pinging_err := pinger.Run()
							if pinging_err != nil {
								color.Red("PING: %s", pinging_err)
								continue
							}

							if pinger.Statistics().PacketLoss > 0 || pinger.Statistics().MinRtt > (time.Duration(conf.MaxPing)*time.Millisecond) {
								color.Red("PING: %s(%s)\t%s\n", domain, ip, pinger.Statistics().MinRtt)
								continue
							}

							minrtt = pinger.Statistics().AvgRtt
						}
						for _, port := range conf.Ports {
							ip := fmt.Sprintf("%s:%d", ip, port)
							// generate http req
							host := conf.Hostname
							if conf.DomainScan.DomainAsHost {
								host = domain
							}
							req := http.Request{Method: "GET", URL: &url.URL{Scheme: scheme, Host: ip, Path: conf.Path}, Host: host}
							req.Header = maps.Clone(conf.Headers)
							req.Header.Set("Host", host)
							if conf.Padding {
								req.Header.Set("Cookie", genPadding(conf.PaddingSize))
							}

							sni := conf.TLS.SNI
							if conf.DomainScan.DomainAsSNI {
								sni = domain
							}
							var client *http.Client
							if conf.TLS.Enable {
								if conf.HTTP3 {
									client = h3transporter(&conf, &sni)
								} else {
									client = tlsTransporter(&conf, &sni)
								}
							} else {
								client = http.DefaultClient
							}

							client.Timeout = time.Millisecond * time.Duration(conf.Maxlatency)
							s := time.Now()
							if conf.TLS.Utls.Enable && conf.TLS.Enable && !conf.HTTP3 {
								uclient, utlsE := utlsTransporter(&conf, fingerprint, &sni, ip)
								if utlsE != nil {
									color.Red("%s", utlsE.Error())
									continue
								}
								client = uclient
							}
							// send request
							respone, http_err := client.Do(&req)
							e := time.Now()
							latency := e.UnixMilli() - s.UnixMilli()
							if http_err != nil {
								color.Red("%s", http_err.Error())
								continue
							}

							if slices.Contains(conf.ResponseStatusCode, respone.StatusCode) && match(respone.Header, conf.ResponseHeader) {
								// Calc jiiter
								jitter_str := "Null"
								download_test := "Null"
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
										color.Red("%s(%s)\t%s\t%d\tJAMMED\n", domain, ip, minrtt, latency)
										continue
									}
									jitter := Calc_jitter(latencies)
									if jitter > conf.MaxJitter {
										color.Yellow("%s(%s)\t%s\t%d\t%f\n", domain, ip, minrtt, latency, jitter)
										continue
									}
									jitter_str = fmt.Sprintf("%f", jitter)
								}
								if conf.DownloadTest.Enable {
									download_test = downloadTest(client, &conf, ip, fingerprint)
								}
								rep := fmt.Sprintf("%s\t%s\t%d\t%s\t%s\n", ip, minrtt, latency, jitter_str, download_test)
								color.Green("%s", rep)
								if conf.CSV {
									ch <- fmt.Sprintf("%s,%s,%d,%s,%s\n", ip, minrtt, latency, jitter_str, download_test)
								} else {
									ch <- rep
								}
							} else {
								color.Red("%s(%s)\t%s\tHTTP.StatusCode=%d\n", domain, ip, minrtt, respone.StatusCode)
							}
						}
					}
				}
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
			csv_file.Write([]byte("ip:port,ping,latency,jitter,download\n"))
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

func h3transporter(conf *Conf, sni *string) *http.Client {
	if sni == nil {
		sni = &conf.TLS.SNI
	}

	tconf := tls.Config{ServerName: *sni, NextProtos: []string{"h3"}, InsecureSkipVerify: conf.TLS.Insecure}
	var h3tr http3.Transport
	if conf.Noise.Enable {
		h3tr = http3.Transport{
			TLSClientConfig: &tconf,
			Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
				udp, udpErr := net.ListenPacket("udp", "0.0.0.0:0")
				if udpErr != nil {
					return nil, udpErr
				}
				uaddr, uaddrErr := net.ResolveUDPAddr("udp", addr)
				if uaddrErr != nil {
					return nil, uaddrErr
				}
				// noise
				var packet []byte = decoder(conf.Noise.Packet)
				udp.WriteTo(packet, uaddr)
				time.Sleep(time.Millisecond * time.Duration(conf.Noise.Sleep))
				return quic.Dial(
					ctx, udp, uaddr, tlsCfg, cfg,
				)
			},
		}
	} else {
		h3tr = http3.Transport{TLSClientConfig: &tconf}
	}
	return &http.Client{
		Transport: &h3tr,
	}
}

func utlsTransporter(conf *Conf, fingerprint utls.ClientHelloID, sni *string, addr string) (*http.Client, error) {
	if sni == nil {
		sni = &conf.TLS.SNI
	}
	dialConn, err := net.DialTimeout("tcp", addr, time.Millisecond*time.Duration(conf.Maxlatency))
	if err != nil {
		return nil, err
	}
	uTlsConn := utls.UClient(dialConn, &utls.Config{ServerName: *sni, InsecureSkipVerify: conf.TLS.Insecure}, fingerprint)
	cx, cxCancel := context.WithTimeout(context.Background(), time.Millisecond*time.Duration(conf.Maxlatency))
	defer cxCancel()
	handshake_e := uTlsConn.HandshakeContext(cx)
	if handshake_e != nil {
		return nil, fmt.Errorf("%s: UTLS handshake timeout", addr)
	}

	if uTlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		h2 := http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				return uTlsConn, nil
			},
		}
		return &http.Client{
			Transport: &h2,
		}, nil
	} else {
		h1 := http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return uTlsConn, nil
			},
		}
		return &http.Client{
			Transport: &h1,
		}, nil
	}
}

func tlsTransporter(conf *Conf, sni *string) *http.Client {
	if sni == nil {
		sni = &conf.TLS.SNI
	}

	tr := http.Transport{
		TLSClientConfig: &tls.Config{ServerName: *sni, InsecureSkipVerify: conf.TLS.Insecure, NextProtos: conf.TLS.Alpn},
		Protocols:       &http.Protocols{},
	}
	tr.Protocols.SetHTTP1(true)
	tr.Protocols.SetHTTP2(true)

	return &http.Client{
		Transport: &tr,
	}
}
