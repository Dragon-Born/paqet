package server

import (
	"context"
	"net"
	"paqet/internal/flog"
	"paqet/internal/pkg/buffer"
	"paqet/internal/protocol"
	"paqet/internal/tnet"
	"time"
)

func (s *Server) handleUDPProtocol(ctx context.Context, strm tnet.Strm, p *protocol.Proto) error {
	flog.Infof("accepted UDP stream %d: %s -> %s", strm.SID(), strm.RemoteAddr(), p.Addr.String())
	return s.handleUDP(ctx, strm, p.Addr.String())
}

func (s *Server) handleUDP(ctx context.Context, strm tnet.Strm, addr string) error {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		flog.Errorf("failed to establish UDP connection to %s for stream %d: %v", addr, strm.SID(), err)
		return err
	}
	defer func() {
		conn.Close()
		flog.Debugf("closed UDP connection %s for stream %d", addr, strm.SID())
	}()
	flog.Debugf("UDP connection established to %s for stream %d", addr, strm.SID())

	errChan := make(chan error, 2)

	// Stream -> target: read length-prefixed frames, write to UDP
	go func() {
		bufp := buffer.UPool.Get().(*[]byte)
		defer buffer.UPool.Put(bufp)
		buf := *bufp

		for {
			select {
			case <-ctx.Done():
				errChan <- nil
				return
			default:
			}

			n, err := buffer.ReadUDPFrame(strm, buf)
			if err != nil {
				errChan <- err
				return
			}

			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Write(buf[:n]); err != nil {
				errChan <- err
				return
			}
			conn.SetWriteDeadline(time.Time{})
		}
	}()

	// Target -> stream: read UDP datagrams, write as length-prefixed frames
	go func() {
		bufp := buffer.UPool.Get().(*[]byte)
		defer buffer.UPool.Put(bufp)
		buf := *bufp

		for {
			select {
			case <-ctx.Done():
				errChan <- nil
				return
			default:
			}

			conn.SetReadDeadline(time.Now().Add(60 * time.Second))
			n, err := conn.Read(buf)
			if err != nil {
				errChan <- err
				return
			}

			if err := buffer.WriteUDPFrame(strm, buf[:n]); err != nil {
				errChan <- err
				return
			}
		}
	}()

	select {
	case err := <-errChan:
		if err != nil {
			flog.Debugf("UDP stream %d to %s ended: %v", strm.SID(), addr, err)
			return err
		}
	case <-ctx.Done():
		return nil
	}

	return nil
}
