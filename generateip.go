package main

import (
	"crypto/rand"
	"log"
	"math/big"
	"net"
	"net/netip"
	"os"
	"strings"
)

func GenIPsFromCIDR(ips *[]string, netCIDR string, subnetMaskSize int, ignoreRange []string, allowRange []string) {
	prefix, err := netip.ParsePrefix(netCIDR)
	if err != nil {
		log.Fatalln(err)
		return
	}

	for _, ignorePrefixStr := range ignoreRange {
		ignorePrefix, err := netip.ParsePrefix(ignorePrefixStr)
		if err != nil {
			log.Fatalln(err)
		}
		if ignorePrefix.Overlaps(prefix) {
			return
		}
	}

	if len(allowRange) > 0 {
		for _, allowPrefixStr := range allowRange {
			allowPrefix, err := netip.ParsePrefix(allowPrefixStr)
			if err != nil {
				log.Fatalln(err)
			}
			if allowPrefix.Overlaps(prefix) {
				for ip := prefix.Addr(); prefix.Contains(ip); ip = ip.Next() {
					*ips = append(*ips, ip.String())
				}
			}
		}
	} else {
		for ip := prefix.Addr(); prefix.Contains(ip); ip = ip.Next() {
			*ips = append(*ips, ip.String())
		}
	}
}

func GenIPs(ips *[]string, ipv4FilePath string, ignoreRange []string, allowRange []string) {
	file, ipListFileErr := os.ReadFile(ipv4FilePath)
	if ipListFileErr != nil {
		log.Fatalln(ipListFileErr)
	}

	for cidr := range strings.Lines(string(file)) {
		GenIPsFromCIDR(ips, strings.TrimSpace(cidr), 24, ignoreRange, allowRange)
	}
}

func randomIPv6FromCIDR(cidr string) (net.IP, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	mask := ipNet.Mask
	ip := ipNet.IP.To16()

	prefixLen, _ := mask.Size()
	totalBits := 128
	variableBits := totalBits - prefixLen

	if variableBits <= 0 {
		return ip, nil
	}

	// Generate a random number for the variable part
	max := new(big.Int).Lsh(big.NewInt(1), uint(variableBits))
	randNum, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}

	ipInt := new(big.Int).SetBytes(ip)

	ipInt.Or(ipInt, randNum)

	// Convert back to net.IP
	randomIP := make(net.IP, 16)
	ipInt.FillBytes(randomIP)

	return randomIP, nil
}
