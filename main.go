package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	probing "github.com/prometheus-community/pro-bing"

	utls "github.com/refraction-networking/utls"
)

type DS struct {
	Enable         bool   `json:"Enable"`
	DomainAsSNI    bool   `json:"DomainAsSNI"`
	DomainAsHost   bool   `json:"DomainAsHost"`
	SkipIPV6       bool   `json:"SkipIPV6"`
	Shuffle        bool   `json:"Shuffle"`
	DomainListPath string `json:"DomainListPath"`
}

type NoisePacket struct {
	Type    string `json:"Type"`
	Payload string `json:"Payload"`
	Sleep   string `json:"Sleep"`
}

type NoiseConfig struct {
	Enable  bool          `json:"Enable"`
	Packets []NoisePacket `json:"Packets"`
}

type DownloadConfig struct {
	Enable             bool   `json:"Enable"`
	SeparateConnection bool   `json:"SeparateConnection"`
	Url                string `json:"Url"`
	SNI                string `json:"SNI"`
	TargetBytes        int    `json:"TargetBytes"`
	Timeout            int    `json:"Timeout"`
}

type UtlsConfig struct {
	Enable      bool   `json:"Enable"`
	Fingerprint string `json:"Fingerprint"`
	TcpTimeout  int64  `json:"TcpTimeout"`
	TcpRetry    int    `json:"TcpRetry"`
}

type TLSConfig struct {
	Enable   bool       `json:"Enable"`
	SNI      string     `json:"SNI"`
	Insecure bool       `json:"Insecure"`
	Alpn     []string   `json:"Alpn"`
	Utls     UtlsConfig `json:"Utls"`
}

type JitterConfig struct {
	Enable    bool    `json:"Enable"`
	MaxJitter float64 `json:"MaxJitter"`
	Samples   int     `json:"Samples"`
	Interval  int64   `json:"Interval"`
}

type PingConfig struct {
	Enable     bool    `json:"Enable"`
	MaxPing    float64 `json:"MaxPing"`
	Privileged bool    `json:"Privileged"`
	Size       string  `json:"Size"`
}

type Conf struct {
	LogErr             bool                `json:"LogErr"`
	CSV                bool                `json:"CSV"`
	RandomScan         bool                `json:"RandomScan"`
	Interface          string              `json:"Interface"`
	Hostname           string              `json:"Hostname"`
	Ports              []int               `json:"Ports"`
	Path               string              `json:"Path"`
	Headers            map[string][]string `json:"Headers"`
	ResponseHeader     map[string]string   `json:"ResponseHeader"`
	ResponseStatusCode []int               `json:"ResponseStatusCode"`
	Padding            bool                `json:"Padding"`
	PaddingSize        string              `json:"PaddingSize"`
	Ping               PingConfig          `json:"Ping"`
	Goroutines         int                 `json:"Goroutines"`
	Scans              int                 `json:"Scans"`
	Maxlatency         int64               `json:"Maxlatency"`
	Jitter             JitterConfig        `json:"Jitter"`
	IpVersion          int                 `json:"IpVersion"`
	IplistPath         string              `json:"IplistPath"`
	IgnoreRange        []string            `json:"IgnoreRange"`
	AllowRange         []string            `json:"AllowRange"`
	TLS                TLSConfig           `json:"TLS"`
	HTTP3              bool                `json:"HTTP/3"`
	Noises             NoiseConfig         `json:"Noises"`
	DomainScan         DS                  `json:"DomainScan"`
	DownloadTest       DownloadConfig      `json:"DownloadTest"`
}

type ResultRow struct {
	Addr     string
	Domain   string
	MinRTT   time.Duration
	Latency  int64
	Jitter   float64
	Download float64
	Err      error
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

	// Download ipv4.txt if not exist
	_, exist := os.Stat("ipv4.txt")
	if exist != nil {
		e := GithubAPI("https://api.github.com/repos/compassvpn/cf-tools/releases/latest", "all_cf_v4.txt", "ipv4.txt")
		if e != nil {
			log.Println("Failed to download ipv4.txt: ", e, "\nFallback to ipv4_old.txt")
			conf.IplistPath = "ipv4_old.txt"
		}
	}

	var ifaceIP net.IP

	ips := make([]string, 0, 256)
	switch conf.IpVersion {
	case 4:
		ifaceIP = net.ParseIP("0.0.0.0")
		// Generate IPs from CIDRs
		color.Yellow("Generating IPs\n")
		GenIPs(&ips, conf.IplistPath, conf.IgnoreRange, conf.AllowRange)
	case 6:
		ifaceIP = net.ParseIP("[::]")
		// Load CIDRs into list and generate random IPv6 during scan
		file, ipListFileErr := os.ReadFile(conf.IplistPath)
		if ipListFileErr != nil {
			log.Fatalln(ipListFileErr)
		}
		ips = strings.Split(string(file), "\n")
	default:
		log.Fatalln("Invalid IP version")
	}

	if conf.Interface != "" {
		iface, getIfaceErr := net.InterfaceByName(conf.Interface)
		if getIfaceErr != nil {
			log.Println(getIfaceErr)
		}

		addrs, getAddrsErr := iface.Addrs()
		if getAddrsErr != nil {
			log.Println(getAddrsErr)
		}

		for _, ip := range addrs {
			ip, _, e := net.ParseCIDR(ip.String())
			if e != nil {
				continue
			}
			switch conf.IpVersion {
			case 4:
				if ip.To4() != nil {
					ifaceIP = ip
				}
			case 6:
				if ip.To4() == nil {
					ifaceIP = ip
				}
			}
		}
	}

	color.Yellow("Interface IP: %s", ifaceIP.String())

	fingerprint := utls.HelloChrome_Auto
	if conf.TLS.Utls.Enable {
		fingerprint = fgen(conf.TLS.Utls.Fingerprint)
	}

	scheme := "http"
	if conf.TLS.Enable {
		scheme = "https"
		if len(conf.Ports) == 0 {
			conf.Ports = append(conf.Ports, 443)
		}
	} else {
		if len(conf.Ports) == 0 {
			conf.Ports = append(conf.Ports, 80)
		}
	}

	LOG := conf.LogErr
	result := make(chan ResultRow, conf.Goroutines)
	color.Green("【ＨＴＴＰ Ｓｃａｎ】\n")
	if !conf.DomainScan.Enable {
		ip_ch := make(chan string, conf.Goroutines)

		// scanners
		for range conf.Goroutines {
			go func() {
				var client *http.Client
				if conf.TLS.Enable {
					if conf.HTTP3 {
						client = h3transporter(&conf, nil, nil)
					} else if !conf.TLS.Utls.Enable {
						client = tlsTransporter(&conf, nil)
					}
				} else {
					client = http.DefaultClient
				}

				for {
					ip, e := <-ip_ch
					if !e {
						break
					}
					minrtt := time.Millisecond
					if conf.Ping.Enable {
						// ping ip
						pinger := probing.New(ip)
						if conf.Interface != "" {
							pinger.InterfaceName = conf.Interface
						}
						pinger.SetPrivileged(conf.Ping.Privileged)
						pinger.Size = randomRange(conf.Ping.Size)
						pinger.Timeout = time.Duration(conf.Ping.MaxPing) * time.Millisecond
						pinger.Count = 1
						pinging_err := pinger.Run()
						if pinging_err != nil {
							if LOG {
								color.Red("PING: %s", pinging_err)
							}
							continue
						}

						if pinger.Statistics().PacketLoss > 0 || pinger.Statistics().MinRtt > (time.Duration(conf.Ping.MaxPing)*time.Millisecond) {
							if LOG {
								color.Red("PING: %s\t%s\n", ip, pinger.Statistics().MinRtt)
							}
							continue
						}

						minrtt = pinger.Statistics().AvgRtt
					}

					for _, port := range conf.Ports {
						addr := fmt.Sprintf("%s:%d", ip, port)

						// generate http req
						var hostname string
						if strings.Contains(conf.Hostname, "{ip}") {
							hostname = ip
						} else {
							hostname = conf.Hostname
						}
						req := http.Request{Method: "GET", URL: &url.URL{Scheme: scheme, Host: addr, Path: conf.Path}, Host: hostname}
						req.Header = maps.Clone(conf.Headers)
						req.Header.Set("Host", hostname)
						if conf.Padding {
							req.Header.Set("Cookie", RandomString(conf.PaddingSize))
						}

						s := time.Now()
						if conf.TLS.Utls.Enable && conf.TLS.Enable && !conf.HTTP3 {
							uclient, utlsE := utlsTransporter(&conf, fingerprint, conf.TLS.SNI, addr, ifaceIP)
							if utlsE != nil {
								result <- ResultRow{
									Addr:     addr,
									Domain:   "",
									MinRTT:   minrtt,
									Latency:  -1,
									Jitter:   -1,
									Download: -1,
									Err:      utlsE,
								}
								continue
							}
							client = uclient
						}
						client.Timeout = time.Millisecond * time.Duration(conf.Maxlatency)
						// send request
						respone, http_err := client.Do(&req)
						e := time.Now()
						latency := e.UnixMilli() - s.UnixMilli()
						if http_err != nil {
							result <- ResultRow{
								Addr:     addr,
								Domain:   "",
								MinRTT:   minrtt,
								Latency:  latency,
								Jitter:   -1,
								Download: -1,
								Err:      http_err,
							}
							continue
						}

						if slices.Contains(conf.ResponseStatusCode, respone.StatusCode) && match(respone.Header, conf.ResponseHeader) {
							// Calc jiiter
							var jitter float64 = -1
							var download_test float64
							var err error
							if conf.Jitter.Enable {
								latencies := []float64{}
								jammed := false
								for range conf.Jitter.Samples {
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
									if conf.Jitter.Interval > 0 {
										time.Sleep(time.Millisecond * time.Duration(conf.Jitter.Interval))
									}
								}
								if jammed {
									result <- ResultRow{
										Addr:     addr,
										Domain:   "",
										MinRTT:   minrtt,
										Latency:  latency,
										Jitter:   jitter,
										Download: -1,
										Err:      errors.New("JAMMED"),
									}
									continue
								}
								jitter = Calc_jitter(latencies)
							}
							if conf.DownloadTest.Enable {
								download_test, err = downloadTest(client, &conf, addr, ifaceIP, fingerprint)
							}

							result <- ResultRow{
								Addr:     addr,
								MinRTT:   minrtt,
								Latency:  latency,
								Jitter:   jitter,
								Download: download_test,
								Err:      err,
							}
						} else {
							result <- ResultRow{
								Addr:    addr,
								MinRTT:  minrtt,
								Latency: latency,
								Jitter:  -1,
								Err:     fmt.Errorf("HTTP.StatusCode=%d", respone.StatusCode),
							}
						}
					}
				}
			}()
		}

		go func() {
			if conf.RandomScan {
				switch conf.IpVersion {
				case 4:
					rand.Shuffle(len(ips), func(i, j int) {
						ips[i], ips[j] = ips[j], ips[i]
					})
					for _, ip := range ips {
						ip_ch <- ip
					}
				case 6:
					for {
						ipv6, e := randomIPv6FromCIDR(strings.TrimSpace(ips[rand.Intn(len(ips))]))
						if e != nil {
							continue
						}
						ip_ch <- fmt.Sprintf("[%s]", ipv6.String())
					}
				}
			} else {
				if conf.IpVersion != 4 {
					log.Fatalln("linear method is only available for ipv4")
				}
				for _, ip := range ips {
					ip_ch <- ip
				}
			}
		}()

		// time.Sleep(time.Duration(conf.Maxlatency*int64(len(conf.Ports))) * time.Millisecond)
	} else {
		// Domain Scan

		var wg sync.WaitGroup

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

		for domainsChunk := range slices.Chunk(domains, len(domains)/conf.Goroutines) {
			wg.Go(func() {
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
						if conf.Ping.Enable {
							// ping ip
							pinger := probing.New(ip.String())
							if conf.Interface != "" {
								pinger.InterfaceName = conf.Interface
							}
							pinger.SetPrivileged(true)
							pinger.Size = randomRange(conf.Ping.Size)
							pinger.Timeout = time.Duration(conf.Ping.MaxPing) * time.Millisecond

							pinger.Count = 1
							pinging_err := pinger.Run()
							if pinging_err != nil {
								if LOG {
									color.Red("PING: %s", pinging_err)
								}
								continue
							}

							if pinger.Statistics().PacketLoss > 0 || pinger.Statistics().MinRtt > (time.Duration(conf.Ping.MaxPing)*time.Millisecond) {
								if LOG {
									color.Red("PING: %s(%s)\t%s\n", domain, ip, pinger.Statistics().MinRtt)
								}
								continue
							}

							minrtt = pinger.Statistics().AvgRtt
						}
						for _, port := range conf.Ports {
							addr := fmt.Sprintf("%s:%d", ip, port)
							// generate http req
							host := conf.Hostname
							if conf.DomainScan.DomainAsHost {
								host = domain
							}
							req := http.Request{Method: "GET", URL: &url.URL{Scheme: scheme, Host: addr, Path: conf.Path}, Host: host}
							req.Header = maps.Clone(conf.Headers)
							req.Header.Set("Host", host)
							if conf.Padding {
								req.Header.Set("Cookie", RandomString(conf.PaddingSize))
							}

							sni := conf.TLS.SNI
							if conf.DomainScan.DomainAsSNI {
								sni = domain
							}
							var client *http.Client
							if conf.TLS.Enable {
								if conf.HTTP3 {
									client = h3transporter(&conf, &sni, nil)
								} else if !conf.TLS.Utls.Enable {
									client = tlsTransporter(&conf, &sni)
								}
							} else {
								client = http.DefaultClient
							}

							s := time.Now()
							if conf.TLS.Utls.Enable && conf.TLS.Enable && !conf.HTTP3 {
								uclient, utlsE := utlsTransporter(&conf, fingerprint, sni, addr, ifaceIP)
								if utlsE != nil {
									result <- ResultRow{
										Addr:     addr,
										Domain:   domain,
										MinRTT:   minrtt,
										Latency:  -1,
										Jitter:   -1,
										Download: -1,
										Err:      utlsE,
									}
									continue
								}
								client = uclient
							}
							client.Timeout = time.Millisecond * time.Duration(conf.Maxlatency)
							// send request
							respone, http_err := client.Do(&req)
							e := time.Now()
							latency := e.UnixMilli() - s.UnixMilli()
							if http_err != nil {
								result <- ResultRow{
									Addr:    addr,
									Domain:  domain,
									MinRTT:  minrtt,
									Latency: latency,
									Jitter:  -1,
									Err:     http_err,
								}
								continue
							}

							if slices.Contains(conf.ResponseStatusCode, respone.StatusCode) && match(respone.Header, conf.ResponseHeader) {
								// Calc jiiter
								var jitter float64 = -1
								var download_test float64
								var err error
								if conf.Jitter.Enable {
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
										if conf.Jitter.Interval > 0 {
											time.Sleep(time.Millisecond * time.Duration(conf.Jitter.Interval))
										}
									}
									if jammed {
										result <- ResultRow{
											Addr:    addr,
											Domain:  domain,
											MinRTT:  minrtt,
											Latency: latency,
											Jitter:  jitter,
											Err:     errors.New("JAMMED"),
										}
										continue
									}
									jitter = Calc_jitter(latencies)
								}
								if conf.DownloadTest.Enable {
									download_test, err = downloadTest(client, &conf, addr, ifaceIP, fingerprint)
								}
								result <- ResultRow{
									Addr:     addr,
									Domain:   domain,
									MinRTT:   minrtt,
									Latency:  latency,
									Jitter:   jitter,
									Download: download_test,
									Err:      err,
								}
							} else {
								result <- ResultRow{
									Addr:    addr,
									Domain:  domain,
									MinRTT:  minrtt,
									Latency: latency,
									Jitter:  -1,
									Err:     fmt.Errorf("HTTP.StatusCode=%d", respone.StatusCode),
								}
							}
						}
					}
				}
			})
		}

		go func() {
			wg.Wait()
			close(result)
		}()
	}

	file := resultFile(conf.CSV)
	defer file.Close()

	for row := range result {
		if row.Err == nil {
			downloadSpeed := "0"
			if row.Download > 0 {
				downloadSpeed = fmt.Sprintf("%fMB/s", row.Download/1024/1024)
			}

			rep := fmt.Sprintf("%s\t%s\t%s\t%d\t%f\t%s\n", row.Addr, row.Domain, row.MinRTT, row.Latency, row.Jitter, downloadSpeed)

			if row.Jitter > conf.Jitter.MaxJitter {
				if LOG {
					color.Yellow("%s", rep)
				}
			} else {
				color.Green("%s", rep)

				if conf.CSV {
					fmt.Fprintf(file, "%s,%s,%s,%d,%f,%s\n", row.Addr, row.Domain, row.MinRTT, row.Latency, row.Jitter, downloadSpeed)
				} else {
					file.Write([]byte(rep))
				}
			}

		} else {
			addr := row.Addr
			if row.Domain != "" {
				addr = fmt.Sprintf("%s(%s)", row.Domain, row.Addr)
			}

			color.Red("%s\t%s", addr, row.Err.Error())
		}

	}
}
