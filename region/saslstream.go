// Copyright (C) 2015  The GoHBase Authors.  All rights reserved.
// This file is part of GoHBase.
// Use of this source code is governed by the Apache License 2.0
// that can be found in the COPYING file.

package region

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"time"

	"github.com/beltran/gosasl"
	"github.com/pkg/errors"
)

const (
	START    = 1
	OK       = 2
	BAD      = 3
	ERROR    = 4
	COMPLETE = 5
)

type SaslConn struct {
	address string
	SaslConf

	conn net.Conn

	saslClient *gosasl.Client
	readBuf    bytes.Buffer

	buffer       [4]byte
	maxLength    uint32
	rawFrameSize uint32 //Current remaining size of the frame. if ==0 read next frame header
	frameSize    int    //Current remaining size of the frame. if ==0 read next frame header
}

func (p *SaslConn) Open(ctx context.Context) (err error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", p.address)
	if err != nil {
		return err
	}
	p.conn = conn

	//step 1. sasl init
	var mechanism gosasl.Mechanism
	if p.MechanismName == "PLAIN" {
		mechanism = gosasl.NewPlainMechanism(p.User, p.Pass)
	} else if p.MechanismName == "GSSAPI" {
		var err error
		mechanism, err = gosasl.NewGSSAPIMechanism(p.Service)
		if err != nil {
			return err
		}
	} else {
		return errors.New("Mechanism not supported")
	}

	addrs := strings.Split(p.address, ":")
	var host string
	if len(addrs) > 0 {
		host = addrs[0]
	} else {
		return errors.New("NewSaslClient Unknown host")
	}

	p.saslClient = gosasl.NewSaslClient(host, mechanism)
	if err = p.sendSaslMsg(ctx, START, []byte(p.MechanismName)); err != nil {
		return err
	}

	proccessed, err := p.saslClient.Start()
	if err != nil {
		return err
	}

	if err = p.sendSaslMsg(ctx, OK, proccessed); err != nil {
		return err
	}

	for true {
		status, challenge := p.recvSaslMsg(ctx)
		if status == OK {
			proccessed, err = p.saslClient.Step(challenge)
			if err != nil {
				return err
			}
			p.sendSaslMsg(ctx, OK, proccessed)
		} else if status == COMPLETE {
			if !p.saslClient.Complete() {
				return errors.New("The server erroneously indicated that SASL negotiation was complete")
			}
			break
		} else {
			return errors.Errorf("Bad SASL negotiation status: %d (%s)", status, challenge)
		}
	}
	return nil
}

// sendSaslMsg
func (p *SaslConn) sendSaslMsg(ctx context.Context, status uint8, body []byte) error {
	header := make([]byte, 5)
	header[0] = status
	length := uint32(len(body))
	binary.BigEndian.PutUint32(header[1:], length)

	_, err := p.conn.Write(append(header[:], body[:]...))
	if err != nil {
		return err
	}
	return nil
}

// recvSaslMsg
func (p *SaslConn) recvSaslMsg(ctx context.Context) (int8, []byte) {
	header := make([]byte, 5)
	_, err := p.readFully(header)
	if err != nil {
		return ERROR, nil
	}

	status := int8(header[0])
	length := binary.BigEndian.Uint32(header[1:])

	if length > 0 {
		payload := make([]byte, length)
		_, err = p.readFully(payload)
		if err != nil {
			return ERROR, nil
		}
		return status, payload
	}
	return status, nil
}

func (s *SaslConn) readFully(buf []byte) (int, error) {
	return io.ReadFull(s.conn, buf)
}

func (p *SaslConn) readFrameHeader() (uint32, error) {
	buf := p.buffer[:4]
	if _, err := p.readFully(buf); err != nil {
		return 0, err
	}
	size := binary.BigEndian.Uint32(buf)
	if size < 0 || size > p.maxLength {
		return 0, errors.Errorf("Incorrect frame size (%d)", size)
	}
	return size, nil
}

func (p *SaslConn) Read(buf []byte) (l int, err error) {
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

func (p *SaslConn) Write(txbuf []byte) (n int, err error) {
	wrappedBuf, err := p.saslClient.Encode(txbuf)
	if err != nil {
		return n, err
	}

	size := len(wrappedBuf)
	buf := p.buffer[:4]
	binary.BigEndian.PutUint32(buf, uint32(size))

	n, err = p.conn.Write(buf)
	if err != nil {
		return n, err
	}

	if size > 0 {
		if n, err := p.conn.Write(wrappedBuf); err != nil {
			print("Error while flushing write buffer of size ", size, " to transport, only wrote ", n, " bytes: ", err.Error(), "\n")
			return n, err
		}
	}
	return len(txbuf), nil
}

func (s *SaslConn) Close() error {
	s.saslClient.Dispose()
	return s.conn.Close()
}

func (s *SaslConn) SetWriteDeadline(t time.Time) error {
	return s.conn.SetWriteDeadline(t)
}

func (s *SaslConn) SetReadDeadline(t time.Time) error {
	return s.conn.SetReadDeadline(t)
}
