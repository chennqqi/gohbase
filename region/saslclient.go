// Copyright (C) 2015  The GoHBase Authors.  All rights reserved.
// This file is part of GoHBase.
// Use of this source code is governed by the Apache License 2.0
// that can be found in the COPYING file.

package region

import (
	"context"
	"encoding/binary"
	"fmt"
	"bytes"
	"io"
	"net"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/beltran/gosasl"
	"github.com/chennqqi/gohbase/hrpc"
	"github.com/chennqqi/gohbase/pb"
	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
)

const (
	START    = 1
	OK       = 2
	BAD      = 3
	ERROR    = 4
	COMPLETE = 5
)

// client manages a connection to a RegionServer.
type saslclient struct {
	*client

	// sasl client
	saslClient *gosasl.Client

	readBuf bytes.Buffer

	buffer       [4]byte
	maxLength    uint32
	rawFrameSize uint32 //Current remaining size of the frame. if ==0 read next frame header
	frameSize    int    //Current remaining size of the frame. if ==0 read next frame header
}

type SaslConf struct {
	MechanismName string
	User, Pass    string
	Service       string
}

// NewClient creates a new RegionClient.
func NewSaslClient(ctx context.Context, addr string, ctype ClientType,
	queueSize int, flushInterval time.Duration, effectiveUser string,
	readTimeout time.Duration, saslConf SaslConf) (hrpc.RegionClient, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to the RegionServer at %s: %s", addr, err)
	}
	c := &client{
		addr:          addr,
		conn:          conn,
		rpcs:          make(chan hrpc.Call),
		done:          make(chan struct{}),
		sent:          make(map[uint32]hrpc.Call),
		rpcQueueSize:  queueSize,
		flushInterval: flushInterval,
		effectiveUser: effectiveUser,
		readTimeout:   readTimeout,
	}

	//step 1. sasl init
	var mechanism gosasl.Mechanism
	if saslConf.MechanismName == "PLAIN" {
		mechanism = gosasl.NewPlainMechanism(saslConf.User, saslConf.Pass)
	} else if saslConf.MechanismName == "GSSAPI" {
		var err error
		mechanism, err = gosasl.NewGSSAPIMechanism(saslConf.Service)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("Mechanism not supported")
	}
	addrs := strings.Split(addr, ":")
	var host string
	if len(addrs) > 0 {
		host = addrs[0]
	} else {
		return nil, errors.New("NewSaslClient Unknown host")
	}
	sasl_client := gosasl.NewSaslClient(host, mechanism)

	p := &saslclient{}
	p.client = c
	p.saslClient = sasl_client

	// sasl init send
	if err = p.sendSaslMsg(ctx, START, []byte(saslConf.mechanism)); err != nil {
		return nil
	}
	
	proccessed, err := p.saslClient.Start()
	if err != nil {
		return nil, err
	}
	if err = p.sendSaslMsg(ctx, OK, proccessed); err != nil {
		return nil, err
	}

	for {
		status, challenge := p.recvSaslMsg(ctx)
		if status == OK {
			proccessed, err = p.saslClient.Step(challenge)
			if err != nil {
				return
			}
			p.sendSaslMsg(ctx, OK, proccessed)
		} else if status == COMPLETE {
			if !p.saslClient.Complete() {
				return nil, errors.New("The server erroneously indicated that SASL negotiation was complete")
			}
			break
		} else {
			return nil, errors.New("The server erroneously indicated that SASL negotiation was complete")

			return nil, errors.Errorf("Bad SASL negotiation status: %d (%s)", status, challenge)
		}
	}

	// time out send hello if it take long
	// TODO: do we even need to bother, we are going to retry anyway?
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetWriteDeadline(deadline)
	}
	if err := c.sendHello(ctype); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send hello to the RegionServer at %s: %s", addr, err)
	}
	// reset write deadline
	conn.SetWriteDeadline(time.Time{})

	if ctype == RegionClient {
		go c.processRPCs() // Batching goroutine
	}
	go c.receiveRPCs() // Reader goroutine
	return salc, nil
}

// sendSaslMsg
func (c *saslclient) sendSaslMsg(ctx context.Context, status uint8, body []byte) error {
	header := make([]byte, 5)
	header[0] = status
	length := uint32(len(body))
	binary.BigEndian.PutUint32(header[1:], length)

	err := c.client.write(append(header[:], body[:]...))
	if err != nil {
		return err
	}
	return nil
}

func (p *saslclient) recvSaslMsg(ctx context.Context) (int8, []byte) {
	header := make([]byte, 5)
	_, err := p.readFully(header)
	if err != nil {
		return ERROR, nil
	}

	status := int8(header[0])
	length := binary.BigEndian.Uint32(header[1:])

	if length > 0 {
		payload := make([]byte, length)
		_, err = io.ReadFull(p.conn, payload)
		if err != nil {
			return ERROR, nil
		}
		return status, payload
	}
	return status, nil
}

// QueueRPC will add an rpc call to the queue for processing by the writer goroutine
func (c *saslclient) QueueRPC(rpc hrpc.Call) {
	if b, ok := rpc.(hrpc.Batchable); ok && c.rpcQueueSize > 1 && !b.SkipBatch() {
		// queue up the rpc
		select {
		case <-rpc.Context().Done():
			// rpc timed out before being processed
		case <-c.done:
			returnResult(rpc, nil, ErrClientDead)
		case c.rpcs <- rpc:
		}
	} else {
		if err := c.trySend(rpc); err != nil {
			returnResult(rpc, nil, err)
		}
	}
}

// Close asks this region.Client to close its connection to the RegionServer.
// All queued and outstanding RPCs, if any, will be failed as if a connection
// error had happened.
func (c *saslclient) Close() {
	c.fail(ErrClientDead)
}

func (c *saslclient) fail(err error) {
	c.once.Do(func() {
		log.WithFields(log.Fields{
			"client": c,
			"err":    err,
		}).Error("error occured, closing region client")

		// we don't close c.rpcs channel to make it block in select of QueueRPC
		// and avoid dealing with synchronization of closing it while someone
		// might be sending to it. Go's GC will take care of it.

		// tell goroutines to stop
		close(c.done)

		// close connection to the regionserver
		// to let it know that we can't receive anymore
		// and fail all the rpcs being sent
		c.conn.Close()

		c.failSentRPCs()
		c.saslClient.Close()
	})
}

func (p *saslclient) saslRead(buf []byte) (l int, err error) {
	if p.rawFrameSize == 0 && p.frameSize == 0 {
		p.rawFrameSize, err = p.readFrameHeader()
		if err != nil {
			return
		}
	}

	var got int
	if p.rawFrameSize > 0 {
		rawBuf := make([]byte, p.rawFrameSize)
		got, err = p.readFully(rawBuf)
		if err != nil {
			return
		}
		p.rawFrameSize = p.rawFrameSize - uint32(got)

		var unwrappedBuf []byte
		unwrappedBuf, err = p.saslClient.Decode(rawBuf)
		if err != nil {
			return
		}
		p.frameSize += len(unwrappedBuf)
		p.readBuf.Write(unwrappedBuf)
	}

	// totalBytes := p.readBuf.Len()
	got, err = p.readBuf.Read(buf)
	p.frameSize = p.frameSize - got

	/*
		if p.readBuf.Len() > 0 {
			err = thrift.NewTTransportExceptionFromError(fmt.Errorf("Not enough frame size %d to read %d bytes", p.frameSize, totalBytes))
			return
		}
	*/
	if p.frameSize < 0 {
		return 0, errors.New("Negative frame size")
	}
	return got, err
}

func (p *saslclient) readFrameHeader() (uint32, error) {
	buf := p.buffer[:4]
	if err := p.readFully(buf); err != nil {
		return 0, err
	}
	size := binary.BigEndian.Uint32(buf)
	if size < 0 || size > p.maxLength {
		return 0, errors.Errorf("Incorrect frame size (%d)", size)
	}
	return size, nil
}

func (c *saslclient) receive() (err error) {
	//TODO::

	var (
		sz       [4]byte
		header   pb.ResponseHeader
		response proto.Message
	)

	err = c.readFully(sz[:])
	if err != nil {
		return UnrecoverableError{err}
	}

	size := binary.BigEndian.Uint32(sz[:])
	b := make([]byte, size)

	_, err = c.saslRead(b)
	if err != nil {
		return UnrecoverableError{err}
	}

	buf := proto.NewBuffer(b)

	if err = buf.DecodeMessage(&header); err != nil {
		return fmt.Errorf("failed to decode the response header: %s", err)
	}
	if header.CallId == nil {
		return ErrMissingCallID
	}

	callID := *header.CallId
	rpc := c.unregisterRPC(callID)
	if rpc == nil {
		return fmt.Errorf("got a response with an unexpected call ID: %d", callID)
	}
	c.inFlightDown()

	select {
	case <-rpc.Context().Done():
		// context has expired, don't bother deserializing
		return
	default:
	}

	// Here we know for sure that we got a response for rpc we asked.
	// It's our responsibility to deliver the response or error to the
	// caller as we unregistered the rpc.
	defer func() { returnResult(rpc, response, err) }()

	if header.Exception == nil {
		response = rpc.NewResponse()
		if err = buf.DecodeMessage(response); err != nil {
			err = fmt.Errorf("failed to decode the response: %s", err)
			return
		}
		var cellsLen uint32
		if header.CellBlockMeta != nil {
			cellsLen = header.CellBlockMeta.GetLength()
		}
		if d, ok := rpc.(canDeserializeCellBlocks); cellsLen > 0 && ok {
			b := buf.Bytes()[size-cellsLen:]
			var nread uint32
			nread, err = d.DeserializeCellBlocks(response, b)
			if err != nil {
				err = fmt.Errorf("failed to decode the response: %s", err)
				return
			}
			if int(nread) < len(b) {
				err = fmt.Errorf("short read: buffer len %d, read %d", len(b), nread)
				return
			}
		}
	} else {
		err = exceptionToError(*header.Exception.ExceptionClassName, *header.Exception.StackTrace)
	}
	return
}

// write sends the given buffer to the RegionServer.
func (p *saslclient) write(txbuf []byte) error {
	wrappedBuf, err := p.saslClient.Encode(txbuf)
	if err != nil {
		return err
	}

	size := len(wrappedBuf)
	buf := p.buffer[:4]
	binary.BigEndian.PutUint32(buf, uint32(size))

	err = p.client.write(buf)
	if err != nil {
		return err
	}

	if size > 0 {
		if err := p.client.write(wrappedBuf); err != nil {
			print("Error while flushing write buffer of size ", size, " to transport, only wrote ", n, " bytes: ", err.Error(), "\n")
			return err
		}
	}
	return nil
}
