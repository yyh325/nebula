// +build !linux android

// udp_generic implements the nebula UDP interface in pure Go stdlib. This
// means it can be used on platforms like Darwin and Windows.

package nebula

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
)

type udpConn struct {
	*net.UDPConn
}

func NewListener(ip string, port int, multi bool) (*udpConn, error) {
	lc := NewListenConfig(multi)
	pc, err := lc.ListenPacket(context.TODO(), "udp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		return nil, err
	}
	if uc, ok := pc.(*net.UDPConn); ok {
		return &udpConn{UDPConn: uc}, nil
	}
	return nil, fmt.Errorf("Unexpected PacketConn: %T %#v", pc, pc)
}

func (uc *udpConn) WriteTo(b []byte, addr *udpAddr) error {
	//TODO: Maybe we just ditch our custom udpAddr entirely
	_, err := uc.UDPConn.WriteToUDP(b, &net.UDPAddr{IP: addr.IP, Port: int(addr.Port)})
	return err
}

func (uc *udpConn) LocalAddr() (*udpAddr, error) {
	a := uc.UDPConn.LocalAddr()

	switch v := a.(type) {
	case *net.UDPAddr:
		addr := &udpAddr{IP: make([]byte, len(v.IP))}
		copy(addr.IP, v.IP)
		addr.Port = uint16(v.Port)
		return addr, nil

	default:
		return nil, fmt.Errorf("LocalAddr returned: %#v", a)
	}
}

func (u *udpConn) reloadConfig(c *Config) {
	// TODO
}

type rawMessage struct {
	Len uint32
}

func (u *udpConn) ListenOut(f *Interface, q int) {
	plaintext := make([]byte, mtu)
	buffer := make([]byte, mtu)
	header := &Header{}
	fwPacket := &FirewallPacket{}
	udpAddr := &udpAddr{IP: make([]byte, 16)}
	nb := make([]byte, 12, 12)

	lhh := f.lightHouse.NewRequestHandler()

	for {
		// Just read one packet at a time
		n, rua, err := u.ReadFromUDP(buffer)
		if err != nil {
			l.WithError(err).Error("Failed to read packets")
			continue
		}

		udpAddr.IP = rua.IP
		udpAddr.Port = uint16(rua.Port)
		f.readOutsidePackets(udpAddr, plaintext[:0], buffer[:n], header, fwPacket, lhh, nb, q)
	}
}

func udp2ip(addr *udpAddr) net.IP {
	return addr.IP
}

func udp2ipInt(addr *udpAddr) uint32 {
	return binary.BigEndian.Uint32(addr.IP.To4())
}

func hostDidRoam(addr *udpAddr, newaddr *udpAddr) bool {
	return !addr.Equals(newaddr)
}
