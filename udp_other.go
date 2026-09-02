//go:build !windows

package main

import (
	"errors"
	"syscall"
)

func udpControl(network, address string, c syscall.RawConn) error {
	return nil
}

func isConnReset(err error) bool {
	return errors.Is(err, syscall.ECONNRESET)
}
