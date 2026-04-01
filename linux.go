//go:build linux

package main

import (
	"net"
	"syscall"
)

func BindDevice(conf *Conf, dial *net.Dialer) {
	dial.Control = func(network, address string, c syscall.RawConn) error {
		var sockErr error
		err := c.Control(func(fd uintptr) {
			sockErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, conf.Interface)
		})
		if err != nil {
			return err
		}
		return sockErr
	}
}
