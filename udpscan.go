package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	probing "github.com/prometheus-community/pro-bing"
)

func UdpScan(conf *Conf) {

	if len(conf.Ports) == 0 {
		conf.Ports = []int{2408, 1701, 500, 4500}
	}

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
						addr := fmt.Sprintf("%s:%d", ip, port)
						latency := sendPacket(conf.UdpScan.Packets, addr, int(conf.Maxlatency))
						rep := fmt.Sprintf("%s\t%s\t%s\n", addr, minrtt, latency)
						if !strings.Contains(latency, "ms") {
							color.Red(rep)
							continue
						}
						color.Green(rep)
						if conf.CSV {
							ch <- fmt.Sprintf("%s,%s,%s\n", addr, minrtt, latency)
						} else {
							ch <- rep
						}
					}
				}
				ch <- "end"
			}()
		}

		file := resultFileUdpScan(conf.CSV)
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
				for {
					ip := <-ip_ch
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
						addr := fmt.Sprintf("%s:%d", ip, port)
						latency := sendPacket(conf.UdpScan.Packets, addr, int(conf.Maxlatency))
						rep := fmt.Sprintf("%s\t%s\t%s\n", addr, minrtt, latency)
						if !strings.Contains(latency, "ms") {
							color.Red(rep)
							continue
						}
						color.Green(rep)
						if conf.CSV {
							res_Ch <- fmt.Sprintf("%s,%s,%s\n", addr, minrtt, latency)
						} else {
							res_Ch <- rep
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
}

func resultFileUdpScan(csv bool) *os.File {
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
			csv_file.Write([]byte("addr,ping,latency\n"))
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

func sendPacket(packet []UdpPayload, addr string, timeout int) string {
	udp, udpE := net.Dial("udp", addr)
	if udpE != nil {
		log.Fatalln(udpE)
	}
	defer udp.Close()

	for _, payload := range packet {
		var payloadBytes []byte = decoder(payload.Payload)
		_, udpWE := udp.Write(payloadBytes)
		if udpWE != nil {
			return "FAILED"
		}
		if payload.Sleep > 0 {
			time.Sleep(time.Millisecond * time.Duration(payload.Sleep))
		}
	}

	ch := make(chan string)
	buf := make([]byte, 1500)
	go func() {
		s := time.Now()
		udp.Read(buf)
		e := time.Now()
		ch <- fmt.Sprintf("%dms", e.UnixMilli()-s.UnixMilli())
	}()

	select {
	case latency := <-ch:
		return latency
	case <-time.After(time.Millisecond * time.Duration(timeout)):
		return "Timeout"
	}
}

func decoder(input string) []byte {
	parts := strings.SplitN(input, "://", 2)
	switch parts[0] {
	case "str":
		return []byte(parts[1])
	case "base64":
		b64, b64E := base64.StdEncoding.DecodeString(parts[1])
		if b64E != nil {
			log.Fatalln(b64E)
		}
		return b64
	case "hex":
		hex, hexE := hex.DecodeString(parts[1])
		if hexE != nil {
			log.Fatalln(hexE)
		}
		return hex
	}

	log.Fatalln("Decoding format not supported")
	return nil
}
