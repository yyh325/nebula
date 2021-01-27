// +build !android

package nebula

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

//TODO: make it support reload as best you can!

type udpConn struct {
	sysFd int
}

var x int

func NewListener(ip string, port int, multi bool) (*udpConn, error) {
	syscall.ForkLock.RLock()
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err == nil {
		unix.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()

	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("unable to open socket: %s", err)
	}

	var lip [16]byte
	copy(lip[:], net.ParseIP(ip))

	if multi {
		if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
			return nil, fmt.Errorf("unable to set SO_REUSEPORT: %s", err)
		}
	}

	//TODO: support multiple listening IPs (for limiting ipv6)
	if err = unix.Bind(fd, &unix.SockaddrInet6{Addr: lip, Port: port}); err != nil {
		return nil, fmt.Errorf("unable to bind to socket: %s", err)
	}

	//TODO: this may be useful for forcing threads into specific cores
	//unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_INCOMING_CPU, x)
	//v, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_INCOMING_CPU)
	//l.Println(v, err)

	return &udpConn{sysFd: fd}, err
}

func (u *udpConn) Rebind() error {
	return nil
}

func (u *udpConn) SetRecvBuffer(n int) error {
	return unix.SetsockoptInt(u.sysFd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, n)
}

func (u *udpConn) SetSendBuffer(n int) error {
	return unix.SetsockoptInt(u.sysFd, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, n)
}

func (u *udpConn) GetRecvBuffer() (int, error) {
	return unix.GetsockoptInt(int(u.sysFd), unix.SOL_SOCKET, unix.SO_RCVBUF)
}

func (u *udpConn) GetSendBuffer() (int, error) {
	return unix.GetsockoptInt(int(u.sysFd), unix.SOL_SOCKET, unix.SO_SNDBUF)
}

func (u *udpConn) LocalAddr() (*udpAddr, error) {
	var rsa unix.RawSockaddrAny
	var rLen = unix.SizeofSockaddrAny

	_, _, err := unix.Syscall(
		unix.SYS_GETSOCKNAME,
		uintptr(u.sysFd),
		uintptr(unsafe.Pointer(&rsa)),
		uintptr(unsafe.Pointer(&rLen)),
	)

	if err != 0 {
		return nil, err
	}

	addr := &udpAddr{}
	if rsa.Addr.Family == unix.AF_INET {
		addr.Port = uint16(rsa.Addr.Data[0])<<8 + uint16(rsa.Addr.Data[1])
		//copy(addr.IP, rsa.Addr.Data[0:4])
		for i, v := range rsa.Addr.Data {
			addr.IP[i] = byte(v)
		}

	} else if rsa.Addr.Family == unix.AF_INET6 {
		//TODO: this cast sucks and we can do better
		pp := (*unix.RawSockaddrInet6)(unsafe.Pointer(&rsa))
		addr.Port = uint16(rsa.Addr.Data[0])<<8 + uint16(rsa.Addr.Data[1])
		copy(addr.IP, pp.Addr[:])

	} else {
		addr.Port = 0
		addr.IP = []byte{}
	}

	return addr, nil
}

func (u *udpConn) ListenOut(f *Interface, q int) {
	plaintext := make([]byte, mtu)
	header := &Header{}
	fwPacket := &FirewallPacket{}
	udpAddr := &udpAddr{}
	nb := make([]byte, 12, 12)

	lhh := f.lightHouse.NewRequestHandler()

	//TODO: should we track this?
	//metric := metrics.GetOrRegisterHistogram("test.batch_read", nil, metrics.NewExpDecaySample(1028, 0.015))
	msgs, buffers, names := u.PrepareRawMessages(f.udpBatchSize)
	read := u.ReadMulti
	if f.udpBatchSize == 1 {
		read = u.ReadSingle
	}

	for {
		n, err := read(msgs)
		if err != nil {
			l.WithError(err).Error("Failed to read packets")
			continue
		}

		//metric.Update(int64(n))
		for i := 0; i < n; i++ {
			udpAddr.IP = names[i][8:24]
			udpAddr.Port = binary.BigEndian.Uint16(names[i][2:4])
			f.readOutsidePackets(udpAddr, plaintext[:0], buffers[i][:msgs[i].Len], header, fwPacket, lhh, nb, q)
		}
	}
}

func (u *udpConn) ReadSingle(msgs []rawMessage) (int, error) {

	for {
		n, _, err := unix.Syscall6(
			unix.SYS_RECVMSG,
			uintptr(u.sysFd),
			uintptr(unsafe.Pointer(&(msgs[0].Hdr))),
			0,
			0,
			0,
			0,
		)

		if err != 0 {
			return 0, &net.OpError{Op: "recvmsg", Err: err}
		}

		msgs[0].Len = uint32(n)
		return 1, nil
	}
}

func (u *udpConn) ReadMulti(msgs []rawMessage) (int, error) {
	for {
		n, _, err := unix.Syscall6(
			unix.SYS_RECVMMSG,
			uintptr(u.sysFd),
			uintptr(unsafe.Pointer(&msgs[0])),
			uintptr(len(msgs)),
			unix.MSG_WAITFORONE,
			0,
			0,
		)

		if err != 0 {
			return 0, &net.OpError{Op: "recvmmsg", Err: err}
		}

		return int(n), nil
	}
}

func (u *udpConn) WriteTo(b []byte, addr *udpAddr) error {
	var rsa unix.RawSockaddrInet6

	//TODO: sometimes addr is nil!
	rsa.Family = unix.AF_INET6
	p := (*[2]byte)(unsafe.Pointer(&rsa.Port))
	p[0] = byte(addr.Port >> 8)
	p[1] = byte(addr.Port)

	copy(rsa.Addr[:], addr.IP)

	for {
		_, _, err := unix.Syscall6(
			unix.SYS_SENDTO,
			uintptr(u.sysFd),
			uintptr(unsafe.Pointer(&b[0])),
			uintptr(len(b)),
			uintptr(0),
			uintptr(unsafe.Pointer(&rsa)),
			uintptr(unix.SizeofSockaddrInet6),
		)

		if err != 0 {
			return &net.OpError{Op: "sendto", Err: err}
		}

		//TODO: handle incomplete writes

		return nil
	}
}

func (u *udpConn) reloadConfig(c *Config) {
	b := c.GetInt("listen.read_buffer", 0)
	if b > 0 {
		err := u.SetRecvBuffer(b)
		if err == nil {
			s, err := u.GetRecvBuffer()
			if err == nil {
				l.WithField("size", s).Info("listen.read_buffer was set")
			} else {
				l.WithError(err).Warn("Failed to get listen.read_buffer")
			}
		} else {
			l.WithError(err).Error("Failed to set listen.read_buffer")
		}
	}

	b = c.GetInt("listen.write_buffer", 0)
	if b > 0 {
		err := u.SetSendBuffer(b)
		if err == nil {
			s, err := u.GetSendBuffer()
			if err == nil {
				l.WithField("size", s).Info("listen.write_buffer was set")
			} else {
				l.WithError(err).Warn("Failed to get listen.write_buffer")
			}
		} else {
			l.WithError(err).Error("Failed to set listen.write_buffer")
		}
	}
}

func hostDidRoam(addr *udpAddr, newaddr *udpAddr) bool {
	return !addr.Equals(newaddr)
}
