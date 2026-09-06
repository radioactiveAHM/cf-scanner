package main

import (
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/base64"
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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	probing "github.com/prometheus-community/pro-bing"
	"golang.org/x/net/http2"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

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

type FragmentConfig struct {
	Enable   bool   `json:"Enable"`
	Length   string `json:"Length"`
	Delay    string `json:"Delay"`
	MaxSplit string `json:"MaxSplit"`
}

type UtlsConfig struct {
	Enable            bool           `json:"Enable"`
	Fingerprint       string         `json:"Fingerprint"`
	TcpTimeout        int64          `json:"TcpTimeout"`
	TcpConnectAttempt int            `json:"TcpConnectAttempt"`
	Fragment          FragmentConfig `json:"Fragment"`
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

func main() {
	// load config file
	cfile, cfile_err := os.ReadFile("conf.json")
	if cfile_err != nil {
		log.Fatalln(cfile_err)
	}
	conf := Conf{}
	conf_err := json.Unmarshal(cfile, &conf)
	if conf_err != nil {
		log.Fatalln(conf_err)
	}

	// Download ipv4.txt if not exist
	// _, exist := os.Stat("ipv4.txt")
	// if exist != nil {
	// 	e := GithubAPI("https://api.github.com/repos/compassvpn/cf-tools/releases/latest", "all_cf_v4.txt", "ipv4.txt")
	// 	if e != nil {
	// 		log.Println("Failed to download ipv4.txt: ", e, "\nFallback to ipv4_old.txt")
	// 		conf.IplistPath = "ipv4_old.txt"
	// 	}
	// }

	ips := make([]string, 0, 256)
	switch conf.IpVersion {
	case 4:
		// Generate IPs from CIDRs
		color.Yellow("Generating IPs\n")
		GenIPs(&ips, conf.IplistPath, conf.IgnoreRange, conf.AllowRange)
	case 6:
		// Load CIDRs into list and generate random IPv6 during scan
		file, ipListFileErr := os.ReadFile(conf.IplistPath)
		if ipListFileErr != nil {
			log.Fatalln(ipListFileErr)
		}
		ips = strings.Split(string(file), "\n")
	default:
		log.Fatalln("Invalid IP version")
	}

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

	LengthMin, LengthMax := parseRange(conf.TLS.Utls.Fragment.Length)
	IntervalMin, IntervalMax := parseRange(conf.TLS.Utls.Fragment.Delay)
	MaxSplitMin, MaxSplitMax := parseRange(conf.TLS.Utls.Fragment.MaxSplit)
	fragment := Fragment{
		PacketsFrom: 0,
		PacketsTo:   1,
		LengthMin:   uint64(LengthMin),
		LengthMax:   uint64(LengthMax),
		IntervalMin: uint64(IntervalMin),
		IntervalMax: uint64(IntervalMax),
		MaxSplitMin: uint64(MaxSplitMin),
		MaxSplitMax: uint64(MaxSplitMax),
	}

	file := FileMutex{
		file: resultFile(conf.CSV),
	}
	defer file.Close()

	LOG := conf.LogErr
	if !conf.DomainScan.Enable {
		ip_ch := make(chan string, conf.Goroutines)
		var wg sync.WaitGroup
		for range conf.Goroutines {
			wg.Go(func() {
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
								color.Red("PING: %s\t%s", ip, pinger.Statistics().MinRtt)
							}
							continue
						}

						minrtt = pinger.Statistics().AvgRtt
					}

					for _, port := range conf.Ports {
						ip := net.ParseIP(ip)
						if ip == nil {
							continue
						}
						addr := net.TCPAddr{IP: ip, Port: port}

						// generate http req
						var hostname string
						if strings.Contains(conf.Hostname, "{ip}") {
							hostname = addr.String()
						} else {
							hostname = conf.Hostname
						}
						req := http.Request{Method: "GET", URL: &url.URL{Scheme: scheme, Host: addr.String(), Path: conf.Path}, Host: hostname, Header: maps.Clone(conf.Headers)}
						req.Header.Set("Host", hostname)
						if conf.Padding {
							req.Header.Set("Cookie", RandomString(conf.PaddingSize))
						}

						s := time.Now()
						if conf.TLS.Utls.Enable && conf.TLS.Enable && !conf.HTTP3 {
							uclient, utlsE := utlsTransporter(&conf, fingerprint, conf.TLS.SNI, addr, &fragment)
							if utlsE != nil {
								if LOG {
									color.Red("%s", utlsE)
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
							if LOG {
								color.Red("%s", http_err)
							}
							continue
						}

						if slices.Contains(conf.ResponseStatusCode, respone.StatusCode) {
							matchHeadersE := matchHeaders(respone.Header, conf.ResponseHeader)
							if matchHeadersE != nil {
								color.Red("%s", matchHeadersE)
								continue
							}
							// Calc jiiter
							jitter_str := "Null"
							download_test := "Null"
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
									if LOG {
										color.Yellow("%s\t%s\t%d\tJAMMED", addr, minrtt, latency)
									}
									continue
								}
								jitter := Calc_jitter(latencies)
								if jitter > conf.Jitter.MaxJitter {
									color.Yellow("%s\t%s\t%d\t%f", addr, minrtt, latency, jitter)
									continue
								}
								jitter_str = fmt.Sprintf("%f", jitter)
							}
							if conf.DownloadTest.Enable {
								download_test = downloadTest(client, &conf, addr, fingerprint, &fragment)
							}
							rep := fmt.Sprintf("%-21s %-12s %d\t%s\t%s\n", addr.String(), minrtt, latency, jitter_str, download_test)
							color.Green("%s", rep)
							if conf.CSV {
								file.Write(fmt.Sprintf("%s,%s,%d,%s,%s\n", addr.String(), minrtt, latency, jitter_str, download_test))
							} else {
								file.Write(rep)
							}
						} else {
							if LOG {
								color.Red("%s\t%s\tHTTP.StatusCode=%d", addr.String(), minrtt, respone.StatusCode)
							}
						}
					}
				}
			})
		}

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
					ip_ch <- ipv6.String()
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
		close(ip_ch)

		wg.Wait()
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

		var wg sync.WaitGroup
		for domainsChunk := range slices.Chunk(domains, len(domains)/conf.Goroutines) {
			wg.Go(func() {
				for _, domain := range domainsChunk {
					domain := strings.TrimSpace(domain)
					ips, resolve_err := net.LookupIP(domain)
					if resolve_err != nil {
						color.HiYellow("%s", resolve_err)
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
									color.Red("PING: %s(%s)\t%s", domain, ip, pinger.Statistics().MinRtt)
								}
								continue
							}

							minrtt = pinger.Statistics().AvgRtt
						}
						for _, port := range conf.Ports {
							addr := net.TCPAddr{IP: ip, Port: port}

							// generate http req
							host := conf.Hostname
							if conf.DomainScan.DomainAsHost {
								host = domain
							}
							req := http.Request{Method: "GET", URL: &url.URL{Scheme: scheme, Host: addr.String(), Path: conf.Path}, Host: host, Header: maps.Clone(conf.Headers)}
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
								uclient, utlsE := utlsTransporter(&conf, fingerprint, sni, addr, &fragment)
								if utlsE != nil {
									if LOG {
										color.Red("%s", utlsE)
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
								if LOG {
									color.Red("%s", http_err)
								}
								continue
							}

							if slices.Contains(conf.ResponseStatusCode, respone.StatusCode) {
								matchHeadersE := matchHeaders(respone.Header, conf.ResponseHeader)
								if matchHeadersE != nil {
									color.Red("%s(%s)\t%s", domain, ip, matchHeadersE)
									continue
								}
								// Calc jiiter
								jitter_str := "Null"
								download_test := "Null"
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
										if LOG {
											color.Yellow("%s(%s)\t%s\t%d\tJAMMED", domain, ip, minrtt, latency)
										}
										continue
									}
									jitter := Calc_jitter(latencies)
									if jitter > conf.Jitter.MaxJitter {
										color.Yellow("%s(%s)\t%s\t%d\t%f", domain, ip, minrtt, latency, jitter)
										continue
									}
									jitter_str = fmt.Sprintf("%f", jitter)
								}
								if conf.DownloadTest.Enable {
									download_test = downloadTest(client, &conf, addr, fingerprint, &fragment)
								}
								rep := fmt.Sprintf("%s:\t%s\t%s\t%d\t%s\t%s\n", domain, ip, minrtt, latency, jitter_str, download_test)
								color.Green("%s", rep)
								if conf.CSV {
									file.Write(fmt.Sprintf("%s:%s,%s,%d,%s,%s\n", domain, ip, minrtt, latency, jitter_str, download_test))
								} else {
									file.Write(rep)
								}
							} else {
								if LOG {
									color.Red("%s(%s)\t%s\tHTTP.StatusCode=%d", domain, ip, minrtt, respone.StatusCode)
								}
							}
						}
					}
				}
			})
		}

		wg.Wait()
	}
}

func matchHeaders(headers http.Header, tomatch map[string]string) error {
	for header, value := range tomatch {
		if headers.Get(header) == value {
			continue
		} else {
			return fmt.Errorf("response header not matching")
		}
	}

	return nil
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

func RandomString(n string) string {
	bytes := make([]byte, randomRange(n))
	_, err := crand.Read(bytes)
	if err != nil {
		log.Fatalln(err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes)
}

func parseRange(r string) (a int, b int) {
	if !strings.Contains(r, "-") {
		return 0, 0
	}

	ab := strings.Split(r, "-")
	a, a_err := strconv.Atoi(ab[0])
	if a_err != nil {
		log.Fatalln(a_err)
	}
	b, b_err := strconv.Atoi(ab[1])
	if b_err != nil {
		log.Fatalln(b_err)
	}

	return a, b
}

func randomRange(r string) int {
	ab := strings.Split(r, "-")
	a, a_err := strconv.Atoi(ab[0])
	if a_err != nil {
		log.Fatalln(a_err)
	}
	b, b_err := strconv.Atoi(ab[1])
	if b_err != nil {
		log.Fatalln(b_err)
	}

	return rand.Intn(b-a+1) + a
}

func h3transporter(conf *Conf, sni *string, qc *quic.Config) *http.Client {
	if sni == nil {
		sni = &conf.TLS.SNI
	}

	tconf := tls.Config{ServerName: *sni, NextProtos: []string{"h3"}, InsecureSkipVerify: conf.TLS.Insecure}
	var h3tr http3.Transport
	if conf.Noises.Enable {
		h3tr = http3.Transport{
			QUICConfig:      qc,
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
				SendNoises(udp, uaddr, conf.Noises.Packets)
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

func utlsTransporter(conf *Conf, fingerprint utls.ClientHelloID, sni string, addr net.TCPAddr, fragment *Fragment) (*http.Client, error) {
	dialer := &net.Dialer{Timeout: time.Millisecond * time.Duration(conf.TLS.Utls.TcpTimeout)}

	var dialConn net.Conn
	var err error
	for reconnect := range conf.TLS.Utls.TcpConnectAttempt {
		dialConn, err = dialer.Dial("tcp", addr.String())
		if err != nil {
			if !errors.Is(err, context.DeadlineExceeded) {
				return nil, err
			}
		} else {
			break
		}

		if reconnect+1 == conf.TLS.Utls.TcpConnectAttempt {
			return nil, err
		}
	}

	uTlsConf := utls.Config{InsecureSkipVerify: conf.TLS.Insecure}
	if strings.Contains(sni, "{ip}") {
		sni = addr.IP.String()
	}
	if sni != "" {
		uTlsConf.ServerName = sni
	}

	if conf.TLS.Utls.Fragment.Enable {
		dialConn = ConnWrap{
			fragment: fragment,
			conn:     dialConn,
			count:    0,
		}
	}

	uTlsConn := utls.UClient(dialConn, &uTlsConf, fingerprint)
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*time.Duration(conf.Maxlatency))
	defer cancel()
	if err := uTlsConn.HandshakeContext(ctx); err != nil {
		uTlsConn.Close()
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("%s: UTLS handshake timeout", addr.String())
		}
		return nil, fmt.Errorf("%s: UTLS handshake error: %w", addr.String(), err)
	}

	if uTlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		return &http.Client{
			Transport: &http2.Transport{
				DialTLSContext: func(_ context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
					return uTlsConn, nil
				},
			},
		}, nil
	} else {
		return &http.Client{
			Transport: &http.Transport{
				DialTLSContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return uTlsConn, nil
				},
			},
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
