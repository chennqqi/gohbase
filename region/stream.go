// Copyright (C) 2015  The GoHBase Authors.  All rights reserved.
// This file is part of GoHBase.
// Use of this source code is governed by the Apache License 2.0
// that can be found in the COPYING file.

package region

import (
	"context"
	"io"
	"net"
	"time"
)

type Stream interface {
	io.ReadWriteCloser

	//	ContextFlusher
	//	ReadSizeProvider

	// Opens the transport for communication
	Open(ctx context.Context) error
	SetWriteDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
}

type StdConn struct {
	net.Conn

	address string
}

func (p *StdConn) Open(ctx context.Context) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", p.address)
	if err != nil {
		return err
	}
	p.Conn = conn
	return err
}
