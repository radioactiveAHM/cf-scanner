package main

import (
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"

	utls "github.com/refraction-networking/utls"
)

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
			csv_file.Write([]byte("ip:port,domain,ping,latency,jitter,download\n"))
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

func utlsTransporter(conf *Conf, fingerprint utls.ClientHelloID, sni string, addr string, localIP net.IP) (*http.Client, error) {
	dialer := &net.Dialer{
		Timeout: time.Millisecond * time.Duration(conf.TLS.Utls.TcpTimeout),
		LocalAddr: &net.TCPAddr{
			IP: localIP,
		},
	}

	if conf.Interface != "" && runtime.GOOS == "linux" {
		BindDevice(conf, dialer)
	}

	var dialConn net.Conn
	var err error
	for reconnect := range conf.TLS.Utls.TcpRetry {
		dialConn, err = dialer.Dial("tcp", addr)
		if err != nil {
			if !errors.Is(err, context.DeadlineExceeded) {
				return nil, err
			}
		} else {
			break
		}

		if reconnect+1 == conf.TLS.Utls.TcpRetry {
			return nil, err
		}
	}

	uTlsConf := utls.Config{InsecureSkipVerify: conf.TLS.Insecure}
	if strings.Contains(sni, "{ip}") {
		sni = strings.Split(addr, ":")[0]
	}
	if sni != "" {
		uTlsConf.ServerName = sni
	}

	uTlsConn := utls.UClient(dialConn, &uTlsConf, fingerprint)
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*time.Duration(conf.Maxlatency))
	defer cancel()
	if err := uTlsConn.HandshakeContext(ctx); err != nil {
		uTlsConn.Close()
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("%s: UTLS handshake timeout", addr)
		}
		return nil, fmt.Errorf("%s: UTLS handshake error: %w", addr, err)
	}

	if uTlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		h2 := http2.Transport{
			DialTLSContext: func(_ context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
				return uTlsConn, nil
			},
		}
		return &http.Client{
			Transport: &h2,
		}, nil
	} else {
		h1 := http.Transport{
			DialTLSContext: func(_ context.Context, _, _ string) (net.Conn, error) {
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
