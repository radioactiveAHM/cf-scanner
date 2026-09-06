package main

import (
	"crypto/rand"
	"math/big"
	"net"
	"time"
)

type Fragment struct {
	PacketsFrom uint64
	PacketsTo   uint64
	LengthMin   uint64
	LengthMax   uint64
	IntervalMin uint64
	IntervalMax uint64
	MaxSplitMin uint64
	MaxSplitMax uint64
}

type ConnWrap struct {
	fragment *Fragment
	conn     net.Conn
	count    uint64
}

func (c ConnWrap) Read(b []byte) (n int, err error) {
	return c.conn.Read(b)
}

func (c ConnWrap) Close() error {
	return c.conn.Close()
}

func (c ConnWrap) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c ConnWrap) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c ConnWrap) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c ConnWrap) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c ConnWrap) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// from github.com/XTLS/Xray-core/blob/main/proxy/freedom/freedom.go
func (f ConnWrap) Write(b []byte) (n int, err error) {
	f.count++

	if f.fragment.PacketsFrom == 0 && f.fragment.PacketsTo == 1 {
		if f.count != 1 || len(b) <= 5 || b[0] != 22 {
			return f.conn.Write(b)
		}
		recordLen := 5 + ((int(b[3]) << 8) | int(b[4]))
		if len(b) < recordLen { // maybe already fragmented somehow
			return f.conn.Write(b)
		}
		data := b[5:recordLen]
		buff := make([]byte, 2048)
		var hello []byte
		maxSplit := RandBetween(int64(f.fragment.MaxSplitMin), int64(f.fragment.MaxSplitMax))
		var splitNum int64
		for from := 0; ; {
			to := from + int(RandBetween(int64(f.fragment.LengthMin), int64(f.fragment.LengthMax)))
			splitNum++
			if to > len(data) || (maxSplit > 0 && splitNum >= maxSplit) {
				to = len(data)
			}
			l := to - from
			if 5+l > len(buff) {
				buff = make([]byte, 5+l)
			}
			copy(buff[:3], b)
			copy(buff[5:], data[from:to])
			from = to
			buff[3] = byte(l >> 8)
			buff[4] = byte(l)
			if f.fragment.IntervalMax == 0 { // combine fragmented tlshello if interval is 0
				hello = append(hello, buff[:5+l]...)
			} else {
				_, err := f.conn.Write(buff[:5+l])
				time.Sleep(time.Duration(RandBetween(int64(f.fragment.IntervalMin), int64(f.fragment.IntervalMax))) * time.Millisecond)
				if err != nil {
					return 0, err
				}
			}
			if from == len(data) {
				if len(hello) > 0 {
					_, err := f.conn.Write(hello)
					if err != nil {
						return 0, err
					}
				}
				if len(b) > recordLen {
					n, err := f.conn.Write(b[recordLen:])
					if err != nil {
						return recordLen + n, err
					}
				}
				return len(b), nil
			}
		}
	}

	if f.fragment.PacketsFrom != 0 && (f.count < f.fragment.PacketsFrom || f.count > f.fragment.PacketsTo) {
		return f.conn.Write(b)
	}
	maxSplit := RandBetween(int64(f.fragment.MaxSplitMin), int64(f.fragment.MaxSplitMax))
	var splitNum int64
	for from := 0; ; {
		to := from + int(RandBetween(int64(f.fragment.LengthMin), int64(f.fragment.LengthMax)))
		splitNum++
		if to > len(b) || (maxSplit > 0 && splitNum >= maxSplit) {
			to = len(b)
		}
		n, err := f.conn.Write(b[from:to])
		from += n
		if err != nil {
			return from, err
		}
		time.Sleep(time.Duration(RandBetween(int64(f.fragment.IntervalMin), int64(f.fragment.IntervalMax))) * time.Millisecond)
		if from >= len(b) {
			return from, nil
		}
	}
}

// from https://github.com/XTLS/Xray-core/blob/main/common/crypto/crypto.go
func RandBetween(from int64, to int64) int64 {
	if from == to {
		return from
	}
	if from > to {
		from, to = to, from
	}
	bigInt, _ := rand.Int(rand.Reader, big.NewInt(to-from))
	return from + bigInt.Int64()
}
