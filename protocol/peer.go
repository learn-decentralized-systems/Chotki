package protocol

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type Peer struct {
	closed atomic.Bool
	wg     sync.WaitGroup

	conn  net.Conn
	inout FeedDrainCloser
}

func (p *Peer) keepRead(ctx context.Context) error {
	var buf bytes.Buffer

	for !p.closed.Load() {
		select {
		case <-ctx.Done():
			break
		default:
			// continue
		}

		if buf.Available() < TYPICAL_MTU {
			buf.Grow(TYPICAL_MTU)
		}

		idle := buf.AvailableBuffer()[:buf.Available()]
		if n, err := p.conn.Read(idle); err != nil {
			if errors.Is(err, io.EOF) {
				time.Sleep(time.Millisecond)
				continue
			}

			return err
		} else {
			buf.Write(idle[:n])
		}

		recs, err := Split(&buf)
		if err != nil {
			return err
		}
		if len(recs) == 0 {
			time.Sleep(time.Millisecond)
			continue
		}
		if err = p.inout.Drain(recs); err != nil {
			return err
		}
	}

	return nil
}

func (p *Peer) keepWrite(ctx context.Context) error {
	for !p.closed.Load() {
		select {
		case <-ctx.Done():
			break
		default:
			// continue
		}

		recs, err := p.inout.Feed()
		if err != nil {
			return err
		}

		b := net.Buffers(recs)
		for len(b) > 0 && err == nil {
			if _, err = b.WriteTo(p.conn); err != nil {
				return err
			}
		}
	}

	return nil
}

func (p *Peer) Keep(ctx context.Context) (rerr, werr, cerr error) {
	p.wg.Add(2) // read & write
	defer p.wg.Add(-2)

	if p.closed.Load() {
		return nil, nil, nil
	}

	readErrCh, writeErrCh := make(chan error, 1), make(chan error, 1)
	go func() { readErrCh <- p.keepRead(ctx) }()
	go func() { writeErrCh <- p.keepWrite(ctx) }()

	for i := 0; i < 2; i++ {
		select {
		case rerr = <-readErrCh:
			if errors.Is(rerr, net.ErrClosed) {
				// That's ok, we probably close it ourselves.
				rerr = nil
			}
		case werr = <-writeErrCh:
			// You can't close it before it's written, but you can close it before it's read.
			// Close after the writing thread has finished, this will cancel all reading threads.
			cerr = p.conn.Close()
		}

		p.closed.Store(true)
	}
	p.conn = nil
	return
}

func (p *Peer) Close() {
	p.closed.Store(true)
	p.wg.Wait()

	if p.conn != nil {
		p.conn.Close()
		p.conn = nil
	}
}
