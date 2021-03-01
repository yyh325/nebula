package nebula

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/rcrowley/go-metrics"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cert"
)

var ErrHostNotKnown = errors.New("host not known")

type LightHouse struct {
	sync.RWMutex //Because we concurrently read and write to our maps
	amLighthouse bool
	myIp         uint32
	punchConn    *udpConn

	// Local cache of answers from light houses
	addrMap map[uint32][]udpAddr

	// filters remote addresses allowed for each host
	// - When we are a lighthouse, this filters what addresses we store and
	// respond with.
	// - When we are not a lighthouse, this filters which addresses we accept
	// from lighthouses.
	remoteAllowList *AllowList

	// filters local addresses that we advertise to lighthouses
	localAllowList *AllowList

	// used to trigger the HandshakeManager when we receive HostQueryReply
	handshakeTrigger chan<- uint32

	// staticList exists to avoid having a bool in each addrMap entry
	// since static should be rare
	staticList  map[uint32]struct{}
	lighthouses map[uint32]struct{}
	interval    int
	nebulaPort  uint32 // 32 bits because protobuf does not have a uint16
	punchBack   bool
	punchDelay  time.Duration

	metrics           *MessageMetrics
	metricHolepunchTx metrics.Counter
}

type EncWriter interface {
	SendMessageToVpnIp(t NebulaMessageType, st NebulaMessageSubType, vpnIp uint32, p, nb, out []byte)
	SendMessageToAll(t NebulaMessageType, st NebulaMessageSubType, vpnIp uint32, p, nb, out []byte)
}

func NewLightHouse(amLighthouse bool, myIp uint32, ips []uint32, interval int, nebulaPort uint32, pc *udpConn, punchBack bool, punchDelay time.Duration, metricsEnabled bool) *LightHouse {
	h := LightHouse{
		amLighthouse: amLighthouse,
		myIp:         myIp,
		addrMap:      make(map[uint32][]udpAddr),
		nebulaPort:   nebulaPort,
		lighthouses:  make(map[uint32]struct{}),
		staticList:   make(map[uint32]struct{}),
		interval:     interval,
		punchConn:    pc,
		punchBack:    punchBack,
		punchDelay:   punchDelay,
	}

	if metricsEnabled {
		h.metrics = newLighthouseMetrics()

		h.metricHolepunchTx = metrics.GetOrRegisterCounter("messages.tx.holepunch", nil)
	} else {
		h.metricHolepunchTx = metrics.NilCounter{}
	}

	for _, ip := range ips {
		h.lighthouses[ip] = struct{}{}
	}

	return &h
}

func (lh *LightHouse) SetRemoteAllowList(allowList *AllowList) {
	lh.Lock()
	defer lh.Unlock()

	lh.remoteAllowList = allowList
}

func (lh *LightHouse) SetLocalAllowList(allowList *AllowList) {
	lh.Lock()
	defer lh.Unlock()

	lh.localAllowList = allowList
}

func (lh *LightHouse) ValidateLHStaticEntries() error {
	for lhIP, _ := range lh.lighthouses {
		if _, ok := lh.staticList[lhIP]; !ok {
			return fmt.Errorf("Lighthouse %s does not have a static_host_map entry", IntIp(lhIP))
		}
	}
	return nil
}

func (lh *LightHouse) Query(ip uint32, f EncWriter) ([]udpAddr, error) {
	if !lh.IsLighthouseIP(ip) {
		lh.QueryServer(ip, f)
	}
	lh.RLock()
	if v, ok := lh.addrMap[ip]; ok {
		lh.RUnlock()
		return v, nil
	}
	lh.RUnlock()
	return nil, ErrHostNotKnown
}

// This is asynchronous so no reply should be expected
func (lh *LightHouse) QueryServer(ip uint32, f EncWriter) {
	if !lh.amLighthouse {
		// Send a query to the lighthouses and hope for the best next time
		query, err := proto.Marshal(NewLhQueryByInt(ip))
		if err != nil {
			l.WithError(err).WithField("vpnIp", IntIp(ip)).Error("Failed to marshal lighthouse query payload")
			return
		}

		lh.metricTx(NebulaMeta_HostQuery, int64(len(lh.lighthouses)))
		nb := make([]byte, 12, 12)
		out := make([]byte, mtu)
		for n := range lh.lighthouses {
			f.SendMessageToVpnIp(lightHouse, 0, n, query, nb, out)
		}
	}
}

// Query our local lighthouse cached results
func (lh *LightHouse) QueryCache(ip uint32) []udpAddr {
	lh.RLock()
	if v, ok := lh.addrMap[ip]; ok {
		lh.RUnlock()
		return v
	}
	lh.RUnlock()
	return nil
}

func (lh *LightHouse) DeleteVpnIP(vpnIP uint32) {
	// First we check the static mapping
	// and do nothing if it is there
	if _, ok := lh.staticList[vpnIP]; ok {
		return
	}
	lh.Lock()
	//l.Debugln(lh.addrMap)
	delete(lh.addrMap, vpnIP)
	l.Debugf("deleting %s from lighthouse.", IntIp(vpnIP))
	lh.Unlock()
}

func (lh *LightHouse) AddRemote(vpnIP uint32, toIp *udpAddr, static bool) {
	// First we check if the sender thinks this is a static entry
	// and do nothing if it is not, but should be considered static
	if static == false {
		if _, ok := lh.staticList[vpnIP]; ok {
			return
		}
	}

	lh.Lock()
	for _, v := range lh.addrMap[vpnIP] {
		if v.Equals(toIp) {
			lh.Unlock()
			return
		}
	}

	allow := lh.remoteAllowList.Allow(toIp.IP)
	l.WithField("remoteIp", toIp).WithField("allow", allow).Debug("remoteAllowList.Allow")
	if !allow {
		return
	}

	//l.Debugf("Adding reply of %s as %s\n", IntIp(vpnIP), toIp)
	if static {
		lh.staticList[vpnIP] = struct{}{}
	}
	lh.addrMap[vpnIP] = append(lh.addrMap[vpnIP], *toIp)
	lh.Unlock()
}

func (lh *LightHouse) AddRemoteAndReset(vpnIP uint32, toIp *udpAddr) {
	if lh.amLighthouse {
		lh.DeleteVpnIP(vpnIP)
		lh.AddRemote(vpnIP, toIp, false)
	}

}

func (lh *LightHouse) IsLighthouseIP(vpnIP uint32) bool {
	if _, ok := lh.lighthouses[vpnIP]; ok {
		return true
	}
	return false
}

func NewLhQueryByInt(VpnIp uint32) *NebulaMeta {
	return &NebulaMeta{
		Type: NebulaMeta_HostQuery,
		Details: &NebulaMetaDetails{
			VpnIp: VpnIp,
		},
	}
}

func NewIpAndPort(ip net.IP, port uint32) IpAndPort {
	ipp := IpAndPort{Port: port}

	if ipv4 := ip.To4(); ipv4 != nil {
		ipp.IpAny = &IpAndPort_Ip{Ip: ip2int(ip)}

	} else {
		ipc := make([]byte, len(ip))
		copy(ipc, ip)
		ipp.IpAny = &IpAndPort_Ipv6{Ipv6: ipc}
	}

	return ipp
}

func NewIpAndPortFromUDPAddr(addr udpAddr) IpAndPort {
	return NewIpAndPort(addr.IP, uint32(addr.Port))
}

func NewUDPAddrFromLH(ipp *IpAndPort) *udpAddr {
	if ipv6 := ipp.GetIpv6(); len(ipv6) > 0 {
		return NewUDPAddr(ipv6, uint16(ipp.Port))
	}

	return NewUDPAddr(int2ip(ipp.GetIp()), uint16(ipp.Port))
}

func (lh *LightHouse) LhUpdateWorker(f EncWriter) {
	if lh.amLighthouse || lh.interval == 0 {
		return
	}

	for {
		var ipps []*IpAndPort

		for _, e := range *localIps(lh.localAllowList) {
			// Only add IPs that aren't my VPN/tun IP
			if ip2int(e) != lh.myIp {
				ipp := NewIpAndPort(e, lh.nebulaPort)
				ipps = append(ipps, &ipp)
			}
		}
		m := &NebulaMeta{
			Type: NebulaMeta_HostUpdateNotification,
			Details: &NebulaMetaDetails{
				VpnIp:      lh.myIp,
				IpAndPorts: ipps,
			},
		}

		lh.metricTx(NebulaMeta_HostUpdateNotification, int64(len(lh.lighthouses)))
		nb := make([]byte, 12, 12)
		out := make([]byte, mtu)
		for vpnIp := range lh.lighthouses {
			mm, err := proto.Marshal(m)
			if err != nil {
				l.Debugf("Invalid marshal to update")
			}
			//l.Error("LIGHTHOUSE PACKET SEND", mm)
			f.SendMessageToVpnIp(lightHouse, 0, vpnIp, mm, nb, out)

		}
		time.Sleep(time.Second * time.Duration(lh.interval))
	}
}

type LightHouseHandler struct {
	lh   *LightHouse
	nb   []byte
	out  []byte
	meta *NebulaMeta
	iap  []IpAndPort
	iapp []*IpAndPort
}

func (lh *LightHouse) NewRequestHandler() *LightHouseHandler {
	lhh := &LightHouseHandler{
		lh:  lh,
		nb:  make([]byte, 12, 12),
		out: make([]byte, mtu),

		meta: &NebulaMeta{
			Details: &NebulaMetaDetails{},
		},
	}

	lhh.resizeIpAndPorts(10)

	return lhh
}

// This method is similar to Reset(), but it re-uses the pointer structs
// so that we don't have to re-allocate them
func (lhh *LightHouseHandler) resetMeta() *NebulaMeta {
	details := lhh.meta.Details

	details.Reset()
	lhh.meta.Reset()
	lhh.meta.Details = details

	return lhh.meta
}

func (lhh *LightHouseHandler) resizeIpAndPorts(n int) {
	if cap(lhh.iap) < n {
		lhh.iap = make([]IpAndPort, n)
		lhh.iapp = make([]*IpAndPort, n)

		for i := range lhh.iap {
			lhh.iapp[i] = &lhh.iap[i]
		}
	}
	lhh.iap = lhh.iap[:n]
	lhh.iapp = lhh.iapp[:n]
}

func (lhh *LightHouseHandler) setIpAndPortsFromNetIps(ips []udpAddr) []*IpAndPort {
	lhh.resizeIpAndPorts(len(ips))
	for i, e := range ips {
		lhh.iap[i] = NewIpAndPortFromUDPAddr(e)
	}
	return lhh.iapp
}

func (lhh *LightHouseHandler) HandleRequest(rAddr *udpAddr, vpnIp uint32, p []byte, c *cert.NebulaCertificate, f EncWriter) {
	lh := lhh.lh
	n := lhh.resetMeta()
	err := proto.UnmarshalMerge(p, n)
	if err != nil {
		l.WithError(err).WithField("vpnIp", IntIp(vpnIp)).WithField("udpAddr", rAddr).
			Error("Failed to unmarshal lighthouse packet")
		//TODO: send recv_error?
		return
	}

	if n.Details == nil {
		l.WithField("vpnIp", IntIp(vpnIp)).WithField("udpAddr", rAddr).
			Error("Invalid lighthouse update")
		//TODO: send recv_error?
		return
	}

	lh.metricRx(n.Type, 1)

	switch n.Type {
	case NebulaMeta_HostQuery:
		// Exit if we don't answer queries
		if !lh.amLighthouse {
			l.Debugln("I don't answer queries, but received from: ", rAddr)
			return
		}

		//l.Debugln("Got Query")
		ips, err := lh.Query(n.Details.VpnIp, f)
		if err != nil {
			//l.Debugf("Can't answer query %s from %s because error: %s", IntIp(n.Details.VpnIp), rAddr, err)
			return
		} else {
			reqVpnIP := n.Details.VpnIp
			n = lhh.resetMeta()
			n.Type = NebulaMeta_HostQueryReply
			n.Details.VpnIp = reqVpnIP
			n.Details.IpAndPorts = lhh.setIpAndPortsFromNetIps(ips)
			reply, err := proto.Marshal(n)
			if err != nil {
				l.WithError(err).WithField("vpnIp", IntIp(vpnIp)).Error("Failed to marshal lighthouse host query reply")
				return
			}
			lh.metricTx(NebulaMeta_HostQueryReply, 1)
			f.SendMessageToVpnIp(lightHouse, 0, vpnIp, reply, lhh.nb, lhh.out[:0])

			// This signals the other side to punch some zero byte udp packets
			ips, err = lh.Query(vpnIp, f)
			if err != nil {
				l.WithField("vpnIp", IntIp(vpnIp)).Debugln("Can't notify host to punch")
				return
			} else {
				//l.Debugln("Notify host to punch", iap)
				n = lhh.resetMeta()
				n.Type = NebulaMeta_HostPunchNotification
				n.Details.VpnIp = vpnIp
				n.Details.IpAndPorts = lhh.setIpAndPortsFromNetIps(ips)
				reply, _ := proto.Marshal(n)
				lh.metricTx(NebulaMeta_HostPunchNotification, 1)
				f.SendMessageToVpnIp(lightHouse, 0, reqVpnIP, reply, lhh.nb, lhh.out[:0])
			}
			//fmt.Println(reply, remoteaddr)
		}

	case NebulaMeta_HostQueryReply:
		if !lh.IsLighthouseIP(vpnIp) {
			return
		}

		for _, a := range n.Details.IpAndPorts {
			ans := NewUDPAddrFromLH(a)
			lh.AddRemote(n.Details.VpnIp, ans, false)
		}

		// Non-blocking attempt to trigger, skip if it would block
		select {
		case lh.handshakeTrigger <- n.Details.VpnIp:
		default:
		}

	case NebulaMeta_HostUpdateNotification:
		//Simple check that the host sent this not someone else
		if n.Details.VpnIp != vpnIp {
			l.WithField("vpnIp", IntIp(vpnIp)).WithField("answer", IntIp(n.Details.VpnIp)).Debugln("Host sent invalid update")
			return
		}

		for _, a := range n.Details.IpAndPorts {
			ans := NewUDPAddrFromLH(a)
			lh.AddRemote(n.Details.VpnIp, ans, false)
		}

	case NebulaMeta_HostMovedNotification:
	case NebulaMeta_HostPunchNotification:
		if !lh.IsLighthouseIP(vpnIp) {
			return
		}

		empty := []byte{0}
		for _, a := range n.Details.IpAndPorts {
			//TODO: only hole punch on ipv4 addresses?
			vpnPeer := NewUDPAddrFromLH(a)
			go func() {
				time.Sleep(lh.punchDelay)
				lh.metricHolepunchTx.Inc(1)
				lh.punchConn.WriteTo(empty, vpnPeer)

			}()

			if l.Level >= logrus.DebugLevel {
				//TODO: lacking the ip we are actually punching on, old: l.Debugf("Punching %s on %d for %s", IntIp(a.Ip), a.Port, IntIp(n.Details.VpnIp))
				l.Debugf("Punching on %d for %s", a.Port, IntIp(n.Details.VpnIp))
			}
		}

		// This sends a nebula test packet to the host trying to contact us. In the case
		// of a double nat or other difficult scenario, this may help establish
		// a tunnel.
		if lh.punchBack {
			go func() {
				time.Sleep(time.Second * 5)
				l.Debugf("Sending a nebula test packet to vpn ip %s", IntIp(n.Details.VpnIp))
				// TODO we have to allocate a new output buffer here since we are spawning a new goroutine
				// for each punchBack packet. We should move this into a timerwheel or a single goroutine
				// managed by a channel.
				f.SendMessageToVpnIp(test, testRequest, n.Details.VpnIp, []byte(""), make([]byte, 12, 12), make([]byte, mtu))
			}()
		}
	}
}

func (lh *LightHouse) metricRx(t NebulaMeta_MessageType, i int64) {
	lh.metrics.Rx(NebulaMessageType(t), 0, i)
}
func (lh *LightHouse) metricTx(t NebulaMeta_MessageType, i int64) {
	lh.metrics.Tx(NebulaMessageType(t), 0, i)
}

/*
func (f *Interface) sendPathCheck(ci *ConnectionState, endpoint *net.UDPAddr, counter int) {
	c := ci.messageCounter
    b := HeaderEncode(nil, Version, uint8(path_check), 0, ci.remoteIndex, c)
	ci.messageCounter++

	if ci.eKey != nil {
		msg := ci.eKey.EncryptDanger(b, nil, []byte(strconv.Itoa(counter)), c)
		//msg := ci.eKey.EncryptDanger(b, nil, []byte(fmt.Sprintf("%d", counter)), c)
		f.outside.WriteTo(msg, endpoint)
		l.Debugf("path_check sent, remote index: %d, pathCounter %d", ci.remoteIndex, counter)
	}
}

func (f *Interface) sendPathCheckReply(ci *ConnectionState, endpoint *net.UDPAddr, counter []byte) {
	c := ci.messageCounter
    b := HeaderEncode(nil, Version, uint8(path_check_reply), 0, ci.remoteIndex, c)
	ci.messageCounter++

	if ci.eKey != nil {
		msg := ci.eKey.EncryptDanger(b, nil, counter, c)
		f.outside.WriteTo(msg, endpoint)
		l.Debugln("path_check sent, remote index: ", ci.remoteIndex)
	}
}
*/
