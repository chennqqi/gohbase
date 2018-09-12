// Copyright (C) 2016  The GoHBase Authors.  All rights reserved.
// This file is part of GoHBase.
// Use of this source code is governed by the Apache License 2.0
// that can be found in the COPYING file.

// +build !testing

package region

import (
	"context"
	"fmt"
	"time"

	"github.com/chennqqi/gohbase/hrpc"
)

type SaslConf struct {
	MechanismName string
	User, Pass    string
	Service       string
}

// NewClient creates a new RegionClient.
func NewClient(ctx context.Context, addr string, ctype ClientType,
	queueSize int, flushInterval time.Duration, effectiveUser string,
	readTimeout time.Duration) (hrpc.RegionClient, error) {
	return NewClientEx(ctx, addr, ctype, queueSize,
		flushInterval, effectiveUser, readTimeout, nil)
}

// NewClient creates a new RegionClient.
func NewClientEx(ctx context.Context, addr string, ctype ClientType,
	queueSize int, flushInterval time.Duration, effectiveUser string,
	readTimeout time.Duration, saslConf *SaslConf) (hrpc.RegionClient, error) {

	var connStream Stream
	if saslConf != nil {
		connStream = &SaslConn{
			address:  addr,
			SaslConf: *saslConf,
		}
	} else {
		connStream = &StdConn{address: addr}
	}

	c := &client{
		addr:          addr,
		conn:          connStream,
		rpcs:          make(chan hrpc.Call),
		done:          make(chan struct{}),
		sent:          make(map[uint32]hrpc.Call),
		rpcQueueSize:  queueSize,
		flushInterval: flushInterval,
		effectiveUser: effectiveUser,
		readTimeout:   readTimeout,
	}
	err := connStream.Open(ctx)
	if err != nil {
		return nil, err
	}

	// time out send hello if it take long
	// TODO: do we even need to bother, we are going to retry anyway?
	if deadline, ok := ctx.Deadline(); ok {
		connStream.SetWriteDeadline(deadline)
	}
	if err := c.sendHello(ctype); err != nil {
		connStream.Close()
		return nil, fmt.Errorf("failed to send hello to the RegionServer at %s: %s", addr, err)
	}
	// reset write deadline
	connStream.SetWriteDeadline(time.Time{})

	if ctype == RegionClient {
		go c.processRPCs() // Batching goroutine
	}
	go c.receiveRPCs() // Reader goroutine
	return c, nil
}
