package socks

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/eycorsican/go-tun2socks/core"
	"github.com/kayrus/tuncfg/log"
	"golang.org/x/net/proxy"
	"io"
	"math/rand"
	"net"
	"sync"
	"time"
)

type udpgwHandler struct {
	proxyHost string
	proxyPort uint16
	udpgwPort uint16

	connIdsMutex sync.Mutex
	connIds      map[core.UDPConn]uint16
	udpConns     map[uint16]core.UDPConn

	socksConnMutex sync.Mutex
	socksConn      net.Conn

	addrsMutex sync.Mutex
	addrs      map[core.UDPConn]*net.UDPAddr
}

func NewUDPGWHandler(proxyHost string, proxyPort uint16, udpgwPort uint16) core.UDPConnHandler {
	rand.Seed(time.Now().Unix())

	handler := &udpgwHandler{
		proxyHost: proxyHost,
		proxyPort: proxyPort,
		udpgwPort: udpgwPort,
		connIds:   make(map[core.UDPConn]uint16),
		udpConns:  make(map[uint16]core.UDPConn),
		addrs:     make(map[core.UDPConn]*net.UDPAddr),
	}

	go handler.readUDPDownstream()

	return handler
}

func (h *udpgwHandler) Connect(conn core.UDPConn, target *net.UDPAddr) error {
	if target == nil {
		return errors.New("target is nil")
	}

	connId := h.generateRandomConnId(conn)

	h.connIdsMutex.Lock()
	h.connIds[conn] = connId
	h.udpConns[connId] = conn
	h.connIdsMutex.Unlock()

	log.Infof("new proxy connection to %v", target.String())

	return nil
}

func (h *udpgwHandler) ReceiveTo(conn core.UDPConn, data []byte, addr *net.UDPAddr) error {
	h.addrsMutex.Lock()
	h.addrs[conn] = addr
	h.addrsMutex.Unlock()

	connId, err := h.getConnId(conn)
	if err != nil {
		return err
	}

	go h.writeUDPUpstream(addr, data, conn, connId)

	return nil
}

func (h *udpgwHandler) readUDPDownstream() {
	buffer := make([]byte, udpgwProtocolMaxMessageSize)

	for {
		socksConn := h.getSocksConn()

		udpgwMessage, err := readUdpgwMessage(socksConn, buffer)
		if err != nil {
			if err != io.EOF {
				h.failedSocksConn(socksConn)
			}
			continue
		}

		udpConn, err := h.getConnById(udpgwMessage.connID)
		if err != nil {
			continue
		}

		h.addrsMutex.Lock()
		addr, addrFound := h.addrs[udpConn]
		h.addrsMutex.Unlock()
		if !addrFound {
			continue
		}

		_, err = udpConn.WriteFrom(udpgwMessage.packet, addr)
		if err != nil {
			h.CloseUDPConn(udpConn)
			continue
		}
	}
}

func (h *udpgwHandler) writeUDPUpstream(
	addr *net.UDPAddr,
	data []byte,
	conn core.UDPConn,
	connId uint16) {
	socksConn := h.getSocksConn()
	destinationIP := addr.IP
	destinationPort := addr.Port
	udpgwPreambleSize := 11

	flags := uint8(0)
	if destinationIP.To4() == nil {
		flags = flags & udpgwProtocolFlagIPv6
		udpgwPreambleSize = 23
	}

	if destinationPort == 53 {
		flags = flags & udpgwProtocolFlagDNS
	}

	reader := bytes.NewReader(data)
	buffer := make([]byte, udpgwProtocolMaxMessageSize)
	for {
		packetSize, err := reader.Read(buffer[udpgwPreambleSize:udpgwProtocolMaxMessageSize])
		if packetSize > udpgwProtocolMaxPayloadSize {
			err = fmt.Errorf("unexpected packet size: %d", packetSize)
		}

		if err != nil {
			if err != io.EOF {
				h.CloseUDPConn(conn)
			}
			return
		}

		err = writeUdpgwPreamble(
			udpgwPreambleSize,
			flags,
			connId,
			destinationIP,
			uint16(destinationPort),
			uint16(packetSize),
			buffer)
		if err != nil {
			h.CloseUDPConn(conn)
			return
		}

		_, err = socksConn.Write(buffer[0 : udpgwPreambleSize+packetSize])
		if err != nil {
			h.CloseUDPConn(conn)
			h.failedSocksConn(socksConn)
			return
		}
	}
}

func (h *udpgwHandler) getSocksConn() net.Conn {
	var socksConn net.Conn

	for {
		h.socksConnMutex.Lock()
		socksConn = h.socksConn
		h.socksConnMutex.Unlock()
		if socksConn != nil {
			break
		}

		h.socksConnMutex.Lock()
		dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("%s:%d", h.proxyHost, h.proxyPort), nil, proxy.Direct)
		if err != nil {
			h.socksConnMutex.Unlock()
			continue
		}

		conn, err := dialer.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", h.udpgwPort))
		if err != nil {
			h.socksConnMutex.Unlock()
			continue
		}

		h.socksConn = conn
		h.socksConnMutex.Unlock()
	}

	return socksConn
}

func (h *udpgwHandler) failedSocksConn(socksConn net.Conn) {
	h.socksConnMutex.Lock()
	if h.socksConn == socksConn {
		h.socksConn.Close()
		h.socksConn = nil
	}
	h.socksConnMutex.Unlock()
}

func (h *udpgwHandler) CloseUDPConn(conn core.UDPConn) {
	conn.Close()

	h.connIdsMutex.Lock()
	defer h.connIdsMutex.Unlock()

	connId, connIdFound := h.connIds[conn]
	if connIdFound {
		delete(h.connIds, conn)
	}

	udpConn, udpConnFound := h.udpConns[connId]
	if udpConnFound {
		delete(h.udpConns, connId)
	}

	_, addrFound := h.addrs[udpConn]
	if addrFound {
		delete(h.addrs, udpConn)
	}
}

func (h *udpgwHandler) generateRandomConnId(conn core.UDPConn) uint16 {
	h.connIdsMutex.Lock()
	defer h.connIdsMutex.Unlock()

	min := 0
	max := 65535
	r := rand.Intn(max-min+1) + min

	if _, ok := h.connIds[conn]; ok {
		return h.generateRandomConnId(conn)
	}

	return uint16(r)
}

func (h *udpgwHandler) getConnId(conn core.UDPConn) (uint16, error) {
	h.connIdsMutex.Lock()
	defer h.connIdsMutex.Unlock()

	connId, found := h.connIds[conn]
	if found {
		return connId, nil
	}

	return 0, errors.New("conn id doesn't exist for this conn")
}

func (h *udpgwHandler) getConnById(connId uint16) (core.UDPConn, error) {
	h.connIdsMutex.Lock()
	defer h.connIdsMutex.Unlock()

	conn, found := h.udpConns[connId]
	if found {
		return conn, nil
	}

	return nil, fmt.Errorf("conn with id %d doesn't exist", connId)
}

// The code below with a minor edit on the writeUdpgwPreamble function is copied from
// https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/ad0a9ee8849b999b32b6c9c2946d63bd3f5dccbf/psiphon/server/udp.go

// TODO: express and/or calculate udpgwProtocolMaxPayloadSize as function of MTU?
const (
	udpgwProtocolFlagKeepalive = 1 << 0
	udpgwProtocolFlagRebind    = 1 << 1
	udpgwProtocolFlagDNS       = 1 << 2
	udpgwProtocolFlagIPv6      = 1 << 3

	udpgwProtocolMaxPreambleSize = 23
	udpgwProtocolMaxPayloadSize  = 32768
	udpgwProtocolMaxMessageSize  = udpgwProtocolMaxPreambleSize + udpgwProtocolMaxPayloadSize
)

type udpgwProtocolMessage struct {
	connID              uint16
	preambleSize        int
	remoteIP            []byte
	remotePort          uint16
	discardExistingConn bool
	forwardDNS          bool
	packet              []byte
}

func readUdpgwMessage(reader io.Reader, buffer []byte) (*udpgwProtocolMessage, error) {
	// udpgw message layout:
	//
	// | 2 byte size | 3 byte header | 6 or 18 byte address | variable length packet |

	for {
		// Read message

		_, err := io.ReadFull(reader, buffer[0:2])
		if err != nil {
			return nil, err
		}

		size := binary.LittleEndian.Uint16(buffer[0:2])

		if size < 3 || int(size) > len(buffer)-2 {
			return nil, errors.New("invalid udpgw message size")
		}

		_, err = io.ReadFull(reader, buffer[2:2+size])
		if err != nil {
			return nil, err
		}

		flags := buffer[2]

		connID := binary.LittleEndian.Uint16(buffer[3:5])

		// Ignore udpgw keep-alive messages -- read another message

		if flags&udpgwProtocolFlagKeepalive == udpgwProtocolFlagKeepalive {
			continue
		}

		// Read address

		var remoteIP []byte
		var remotePort uint16
		var packetStart, packetEnd int

		if flags&udpgwProtocolFlagIPv6 == udpgwProtocolFlagIPv6 {

			if size < 21 {
				return nil, errors.New("invalid udpgw message size")
			}

			remoteIP = make([]byte, 16)
			copy(remoteIP, buffer[5:21])
			remotePort = binary.BigEndian.Uint16(buffer[21:23])
			packetStart = 23
			packetEnd = 23 + int(size) - 21

		} else {

			if size < 9 {
				return nil, errors.New("invalid udpgw message size")
			}

			remoteIP = make([]byte, 4)
			copy(remoteIP, buffer[5:9])
			remotePort = binary.BigEndian.Uint16(buffer[9:11])
			packetStart = 11
			packetEnd = 11 + int(size) - 9
		}

		// Assemble message
		// Note: udpgwProtocolMessage.packet references memory in the input buffer

		message := &udpgwProtocolMessage{
			connID:              connID,
			preambleSize:        packetStart,
			remoteIP:            remoteIP,
			remotePort:          remotePort,
			discardExistingConn: flags&udpgwProtocolFlagRebind == udpgwProtocolFlagRebind,
			forwardDNS:          flags&udpgwProtocolFlagDNS == udpgwProtocolFlagDNS,
			packet:              buffer[packetStart:packetEnd],
		}

		return message, nil
	}
}

func writeUdpgwPreamble(
	preambleSize int,
	flags uint8,
	connID uint16,
	destinationIP net.IP,
	remotePort uint16,
	packetSize uint16,
	buffer []byte) error {
	remoteIP := destinationIP[len(destinationIP)-4:]

	if preambleSize != 7+len(remoteIP) {
		return errors.New("invalid udpgw preamble size")
	}

	size := uint16(preambleSize-2) + packetSize

	// size
	binary.LittleEndian.PutUint16(buffer[0:2], size)

	// flags
	buffer[2] = flags

	// connID
	binary.LittleEndian.PutUint16(buffer[3:5], connID)

	// addr
	copy(buffer[5:5+len(remoteIP)], remoteIP)
	binary.BigEndian.PutUint16(buffer[5+len(remoteIP):7+len(remoteIP)], remotePort)

	return nil
}
