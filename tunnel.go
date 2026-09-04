package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	BIND_TIMEOUT   = 10 * time.Second
	RETRY_ATTEMPTS = 3
	RETRY_DELAY    = 2 * time.Second
	CSEQ_BASE      = 100
	CSEQ_STEP      = 1000
)

var (
	HEARTBEAT_TIMEOUT  = 10 * time.Second
	RELAY_READ_TIMEOUT = 15 * time.Second
)

var errDeviceNotFound = errors.New("device response: code=404 Not Found")

var notFoundPrinted sync.Once

func deviceNotFound(serial string) {
	notFoundPrinted.Do(func() {
		fmt.Printf("%s doesn't exist or turned off.\n", serial)
	})
}

func isNotFound(reason string) bool {
	return reason == errDeviceNotFound.Error()
}

var ptcpHeartbeat = []byte{
	0x13, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
}

type PortSpec struct {
	Local  int
	Remote int
}

type Client struct {
	conn          net.Conn
	lastKeepalive time.Time
	cseq          int
	remotePort    int

	// Downstream coalescing: the device streams 1280-byte DATA frames;
	// writing each to the browser as a separate TCP segment makes chatty
	// protocols (HTTP) crawl while bulk video hides the cost.
	flushMu    sync.Mutex
	pending    []byte
	flushTimer *time.Timer
}

const (
	coalesceDelay = 2 * time.Millisecond
	coalesceMax   = 16 * 1024
)

// writeData buffers a downstream fragment and flushes to the client socket
// either when the batch fills or after coalesceDelay elapses.
func (c *Client) writeData(b []byte) {
	c.flushMu.Lock()
	c.pending = append(c.pending, b...)
	if len(c.pending) >= coalesceMax {
		out := c.pending
		c.pending = nil
		if c.flushTimer != nil {
			c.flushTimer.Stop()
			c.flushTimer = nil
		}
		c.flushMu.Unlock()
		c.conn.Write(out)
		return
	}
	if c.flushTimer == nil {
		c.flushTimer = time.AfterFunc(coalesceDelay, c.flushNow)
	}
	c.flushMu.Unlock()
}

// flushNow drains the pending batch (timer callback or forced).
func (c *Client) flushNow() {
	c.flushMu.Lock()
	out := c.pending
	c.pending = nil
	c.flushTimer = nil
	c.flushMu.Unlock()
	if len(out) > 0 {
		c.conn.Write(out)
	}
}

type acceptConn struct {
	conn       net.Conn
	remotePort int
}

type specGroup struct {
	idxs  []int
	specs []PortSpec
}

// Tunnel owns one connection cycle to a device: cloud handshake, NAT punch,
// PTCP session, and the local TCP listeners multiplexed over it.
type Tunnel struct {
	serial, username, password, randsalt string
	dtype                                int
	debug                                bool
	logRetries                           bool
	useTCP                               bool // force TCP-relay data path

	specs   []PortSpec
	specIdx []int
	reg     *PortRegistry
	ui      *UI
	progress *ConnectProgress // non-nil only in single-port mode

	deviceRemote *UDP
	mainRemote   *UDP
	primary      *UDP // data path: deviceRemote (direct) or mainRemote (relay)
	useTCPPath   bool // active data path is the TCP relay channel
	tou          *touChannel
	listeners    []net.Listener
	clients      map[uint32]*Client
	clientsMu    sync.Mutex
	acceptCh     chan acceptConn
	done         chan struct{}
	cseqCounter  int

	readerWG  sync.WaitGroup // readLoop + heartbeatLoop goroutines
	bindMu    sync.Mutex
	bindWait  map[uint32]chan struct{}
	bindReqMu sync.Mutex // serializes BIND requests
	socksMu   sync.Mutex
	errMu     sync.Mutex
	failErr   error

	// Realm pool: pre-bound realms per remote port. The camera's web server
	// closes HTTP connections, so browsers reconnect per request; a pooled
	// pre-bound realm removes the BIND round-trip from the critical path.
	// A keeper goroutine maintains the fixed level; in-flight binds are
	// tracked so refills never overshoot.
	poolMu     sync.Mutex
	pools      map[int]*poolState
	poolTarget int
}


// poolState is the per-port pool. All fields guarded by poolMu.
type poolState struct {
	queue    []uint32
	inflight int
}

func newTunnel(serial string, dtype int, username, password, randsalt string, debug, logRetries bool, forceTCP bool, poolSize int, g specGroup, reg *PortRegistry) *Tunnel {
	t := &Tunnel{
		serial:      serial,
		dtype:       dtype,
		username:    username,
		password:    password,
		randsalt:    randsalt,
		debug:       debug,
		logRetries:  logRetries,
		useTCP:      forceTCP,
		poolTarget:  poolSize,
		specs:       g.specs,
		specIdx:     g.idxs,
		reg:         reg,
		cseqCounter: CSEQ_BASE,
	}
	if reg != nil {
		t.ui = reg.ui
	}
	t.reset()
	return t
}

// reset prepares a fresh generation. readerWG.Wait() drains stale readers from
// the previous attempt so they cannot poison the new state.
func (t *Tunnel) reset() {
	t.readerWG.Wait()
	t.listeners = nil
	t.clients = make(map[uint32]*Client)
	t.acceptCh = make(chan acceptConn, 16)
	t.done = make(chan struct{})
	t.cseqCounter = CSEQ_BASE
	t.socksMu.Lock()
	t.deviceRemote = nil
	t.mainRemote = nil
	t.tou = nil
	t.useTCPPath = false
	t.socksMu.Unlock()
	t.primary = nil
	t.bindWait = make(map[uint32]chan struct{})
	t.pools = make(map[int]*poolState)
	t.failErr = nil
}

func (t *Tunnel) close() {
	select {
	case <-t.done:
	default:
		close(t.done)
	}
	for _, ln := range t.listeners {
		ln.Close()
	}
	t.clientsMu.Lock()
	for _, c := range t.clients {
		c.conn.Close()
	}
	t.clientsMu.Unlock()
	t.socksMu.Lock()
	dr, mr, tou := t.deviceRemote, t.mainRemote, t.tou
	t.socksMu.Unlock()
	if dr != nil {
		dr.Close()
	}
	if mr != nil {
		mr.Close()
	}
	if tou != nil {
		tou.close()
	}
}

func (t *Tunnel) Run() error {
	if err := t.handshake(); err != nil {
		t.close()
		return err
	}
	defer t.close()
	return t.serve()
}

func (t *Tunnel) logf(format string, args ...any) {
	if !t.debug {
		return
	}
	msg := fmt.Sprintf(format, args...)
	if t.ui != nil {
		t.ui.Below(msg)
	} else {
		fmt.Println(msg)
	}
}

// statusf advances the progress bar to the given phase.
// In debug mode the status is also emitted as a log line.
func (t *Tunnel) statusf(phase int, status string) {
	if t.progress != nil {
		t.progress.Phase(phase, status)
	}
	t.logf("[phase %d] %s", phase, status)
}

func (t *Tunnel) markConnecting() {
	if t.reg == nil {
		return
	}
	for _, idx := range t.specIdx {
		t.reg.connecting(idx)
	}
}

// p2pChannelBody builds the /device/<SN>/p2p-channel XML body: Identify (8
// random bytes space-separated), IpEncrpt flag, and (Type 1) the signed and
// encrypted auth block.
func p2pChannelBody(lport, dtype int, username, password, randsalt string, aid []byte) (string, []byte) {
	laddr := fmt.Sprintf("127.0.0.1:%d", lport)
	ipaddr := fmt.Sprintf("<IpEncrpt>true</IpEncrpt><LocalAddr>%s</LocalAddr>", laddr)
	authStr := ""
	var key []byte
	if dtype > 0 {
		key = getDeriveKey(username, password, randsalt)
		encNonce := getNonce()
		encLaddr := getEnc(key, encNonce, laddr)
		ipaddr = fmt.Sprintf("<IpEncrptV2>true</IpEncrptV2><LocalAddr>%s</LocalAddr>", encLaddr)
		authStr = getAuth(username, key, encNonce, laddr, randsalt)
	}

	aidHex := make([]string, 8)
	for i, b := range aid {
		aidHex[i] = fmt.Sprintf("%x", b)
	}

	body := fmt.Sprintf("<body>%s<Identify>%s</Identify>%s<version>5.0.0</version></body>",
		authStr, strings.Join(aidHex, " "), ipaddr)
	return body, key
}

// handshake runs the full 4-phase connection: cloud discovery, relay agent
// allocation, Server Nat Info, inverted STUN punch and PTCP negotiation.
// On STUN success t.primary = deviceRemote (direct), otherwise mainRemote
// (relay agent).
func (t *Tunnel) handshake() error {
	mainRemote := NewUDP(MAIN_SERVER, MAIN_PORT, t.debug)
	mainRemote.debugLog = t.logf
	t.socksMu.Lock()
	t.mainRemote = mainRemote
	t.socksMu.Unlock()
	if mainRemote.initErr != nil {
		return fmt.Errorf("main socket: %v", mainRemote.initErr)
	}

	// Phase 1: cloud discovery.
	t.statusf(PhaseCloudLookup, "cloud lookup")
	mainRemote.Request("/probe/p2psrv", "", true, true)
	res, _ := mainRemote.Request(fmt.Sprintf("/online/p2psrv/%s", t.serial), "", true, true)
	if res == nil {
		return fmt.Errorf("p2psrv lookup failed")
	}
	us := res.Body["body/US"]
	if us == "" {
		return fmt.Errorf("device %s not found on p2psrv", t.serial)
	}
	p2psrv := strings.SplitN(us, ":", 2)
	p2psrvPort, _ := strconv.Atoi(p2psrv[1])

	// Warm-up probes to the device's P2P server (US).
	t.statusf(PhaseDeviceProbe, "device probe")
	p2psrvRemote := NewUDP(p2psrv[0], p2psrvPort, t.debug)
	p2psrvRemote.debugLog = t.logf
	p2psrvRemote.Request(fmt.Sprintf("/probe/device/%s", t.serial), "", true, true)
	p2psrvRemote.Request(fmt.Sprintf("/info/device/%s", t.serial), "", true, true)
	p2psrvRemote.Close()

	// Phase 2: relay dispatcher lookup.
	t.statusf(PhaseRelayAlloc, "relay lookup")
	res, err := mainRemote.Request("/online/relay", "", true, true)
	if err != nil {
		return fmt.Errorf("relay lookup: %v", err)
	}
	relay := strings.SplitN(res.Body["body/Address"], ":", 2)
	relayPort, _ := strconv.Atoi(relay[1])

	// Data socket for the device side, bound through the main cloud host.
	deviceRemote := NewUDP(MAIN_SERVER, MAIN_PORT, t.debug)
	deviceRemote.debugLog = t.logf
	t.socksMu.Lock()
	t.deviceRemote = deviceRemote
	t.socksMu.Unlock()
	if deviceRemote.initErr != nil {
		return fmt.Errorf("device socket: %v", deviceRemote.initErr)
	}

	if t.dtype > 0 && (t.username == "" || t.password == "") {
		return fmt.Errorf("username and password required for type > 0")
	}

	// Phase 3: p2p-channel request with a random 8-byte session id (AID).
	t.statusf(PhaseP2PChannel, "p2p-channel")
	aid := make([]byte, 8)
	rand.Read(aid)
	body, key := p2pChannelBody(deviceRemote.lport, t.dtype, t.username, t.password, t.randsalt, aid)

	deviceRemote.Request(fmt.Sprintf("/device/%s/p2p-channel", t.serial), body, true, false)

	// Relay agent allocation on the main socket.
	t.statusf(PhaseRelayAlloc, "relay agent alloc")
	mainRemote.SetRemote(relay[0], relayPort)
	res, err = mainRemote.Request("/relay/agent", "", true, true)
	if err != nil {
		return fmt.Errorf("relay agent: %v", err)
	}
	token := res.Body["body/Token"]
	agent := res.Body["body/Agent"]

	agentParts := strings.SplitN(agent, ":", 2)
	agentPort, _ := strconv.Atoi(agentParts[1])

	mainRemote.SetRemote(agentParts[0], agentPort)
	mainRemote.Request(fmt.Sprintf("/relay/start/%s", token), "<body><Client>:0</Client></body>", true, true)

	// Phase 4: Server Nat Info from the device (via cloud/US).
	t.statusf(PhaseP2PChannel, "waiting for device ack")
	t.logf("waiting for p2p-channel ack (timeout %.0fs)", RELAY_READ_TIMEOUT.Seconds())
	res, err = deviceRemote.Read(true, RELAY_READ_TIMEOUT)
	if err == nil && res.Code < 200 {
		t.logf("waiting for p2p-channel ack body (timeout %.0fs)", RELAY_READ_TIMEOUT.Seconds())
		res, err = deviceRemote.Read(true, RELAY_READ_TIMEOUT)
	}
	if err != nil {
		return fmt.Errorf("read device response: %v", err)
	}
	if res.Code >= 400 {
		if res.Code == 404 {
			return errDeviceNotFound
		}
		if t.dtype == 0 && res.Code == 403 {
			return fmt.Errorf("device requires authentication, try --type 1 --username <user> --password <pass>")
		}
		return fmt.Errorf("device response: code=%d %s", res.Code, res.Status)
	}

	deviceLaddr := res.Body["body/LocalAddr"]
	devicePub := res.Body["body/PubAddr"]

	if t.dtype > 0 {
		nonceStr := res.Body["body/Nonce"]
		if nonceStr != "" {
			nonceVal, _ := strconv.Atoi(nonceStr)
			deviceLaddr = getDec(key, nonceVal, deviceLaddr)
		}
	}

	devParts := strings.SplitN(devicePub, ":", 2)
	devPort, _ := strconv.Atoi(devParts[1])
	deviceRemote.SetRemote(devParts[0], devPort)

	// Notify the device about the relay agent.
	// If the relay agent doesn't ack in time we retry once: cloud sometimes
	// takes a few extra seconds to propagate the relay assignment.
	t.statusf(PhaseRelayChannel, "relay-channel")
	mainRemote.SetRemote(MAIN_SERVER, MAIN_PORT)
	authStr := ""
	if t.dtype > 0 {
		nonce2 := getNonce()
		authStr = getAuth(t.username, key, nonce2, "", t.randsalt)
	}
	sendRelayChannel := func() {
		mainRemote.Request(fmt.Sprintf("/device/%s/relay-channel", t.serial),
			fmt.Sprintf("<body>%s<agentAddr>%s:%d</agentAddr></body>", authStr, agentParts[0], agentPort),
			true, false)
	}
	sendRelayChannel()
	mainRemote.SetRemote(agentParts[0], agentPort)
	t.logf("waiting for relay-channel ack from agent %s:%d (timeout %.0fs)", agentParts[0], agentPort, RELAY_READ_TIMEOUT.Seconds())
	if _, err := mainRemote.Read(true, RELAY_READ_TIMEOUT); err != nil {
		// Retry: send relay-channel once more and wait again.
		// The cloud sometimes takes several extra seconds to propagate the
		// relay assignment to the agent; a single retry covers this case.
		t.logf("relay-channel ack timed out (%v) — retrying", err)
		t.statusf(PhaseRelayChannel, "relay-channel retry")
		mainRemote.SetRemote(MAIN_SERVER, MAIN_PORT)
		sendRelayChannel()
		mainRemote.SetRemote(agentParts[0], agentPort)
		t.logf("waiting for relay-channel ack (retry, timeout %.0fs)", RELAY_READ_TIMEOUT.Seconds())
		if _, err2 := mainRemote.Read(true, RELAY_READ_TIMEOUT); err2 != nil {
			return fmt.Errorf("relay-channel read: %v", err2)
		}
	}

	policy := res.Body["body/Policy"]
	tcpRelayAllowed := strings.Contains(policy, "tcprelay")

	// Forced TCP-relay mode: the TOU channel replaces PTCP-over-UDP entirely.
	if t.useTCP {
		t.statusf(PhasePTCPHandshake, "TCP relay attach")
		if err := t.attachTCPRelay(agentParts[0], agentPort, token); err != nil {
			return err
		}
		t.logf("TCP relay channel attached (forced)")
		return nil
	}

	// PTCP over relay: SYNC then token request (0x17 -> 0x18).
	t.statusf(PhaseNATPunch, "PTCP sync")
	mainRemote.RequestPTCP([]byte{0x00, 0x03, 0x01, 0x00})
	t.logf("waiting for ptcp sync (timeout %.0fs)", RELAY_READ_TIMEOUT.Seconds())
	p, err := mainRemote.ReadPTCP(RELAY_READ_TIMEOUT)
	if err != nil {
		// UDP relay path dead — try the TCP relay channel if the device
		// advertises tcprelay support in its policy list.
		if tcpRelayAllowed {
			t.logf("ptcp sync over UDP failed (%v) — policy allows tcprelay, trying TCP relay", err)
			t.statusf(PhasePTCPHandshake, "TCP relay fallback")
			if aerr := t.attachTCPRelay(agentParts[0], agentPort, token); aerr == nil {
				t.logf("TCP relay channel attached (fallback)")
				return nil
			} else {
				t.logf("TCP relay fallback failed: %v", aerr)
			}
		}
		return fmt.Errorf("ptcp sync: %v", err)
	}

	t.statusf(PhaseNATPunch, "PTCP token")
	mainRemote.RequestPTCP([]byte{
		0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	})
	t.logf("waiting for ptcp 0x17 (timeout %.0fs)", RELAY_READ_TIMEOUT.Seconds())
	p, err = mainRemote.ReadPTCP(RELAY_READ_TIMEOUT)
	if err != nil {
		return fmt.Errorf("ptcp 0x17: %v", err)
	}
	for len(p.Body) == 0 {
		t.logf("waiting for ptcp 0x17 body (timeout %.0fs)", RELAY_READ_TIMEOUT.Seconds())
		p, err = mainRemote.ReadPTCP(RELAY_READ_TIMEOUT)
		if err != nil {
			return fmt.Errorf("ptcp 0x17 wait: %v", err)
		}
	}
	sign := p.Body[12:]
	mainRemote.RequestPTCP(nil)

	// Inverted STUN punch (Level 2): build the Init packet from the AID.
	t.statusf(PhaseNATPunch, "NAT punch")
	invAid := make([]byte, 8)
	for i, b := range aid {
		invAid[i] = ^b
	}

	cookie := make([]byte, 4)
	rand.Read(cookie)
	transID := make([]byte, 12)
	rand.Read(transID)

	eaddr := make([]byte, 6)
	binary.BigEndian.PutUint16(eaddr[0:2], uint16(devPort))
	copy(eaddr[2:], net.ParseIP(devParts[0]).To4())
	for i, b := range eaddr {
		eaddr[i] = ^b
	}

	stunInit := []byte{0xFF, 0xFE, 0xFF, 0xE7}
	stunInit = append(stunInit, cookie...)
	stunInit = append(stunInit, transID...)
	stunInit = append(stunInit, []byte{0x7F, 0xD5, 0xFF, 0xF7}...)
	stunInit = append(stunInit, invAid...)
	stunInit = append(stunInit, []byte{0xFF, 0xFB, 0xFF, 0xF7, 0xFF, 0xFE}...)
	stunInit = append(stunInit, eaddr...)

	localIPStr, localPortStr, _ := strings.Cut(deviceLaddr, ":")
	localPortVal, _ := strconv.Atoi(localPortStr)

	t.logf(":%d >>> %s:%d (LocalAddr)", deviceRemote.lport, localIPStr, localPortVal)
	t.logf(":%d >>> %s:%d (PubAddr)", deviceRemote.lport, devParts[0], devPort)

	deviceRemote.SendTo(stunInit, &net.UDPAddr{IP: net.ParseIP(localIPStr), Port: localPortVal})
	deviceRemote.Send(stunInit)

	var stunResponse []byte
	deviceRemote.SetTimeout(2 * time.Second)
	deadline := time.Now().Add(10 * time.Second)
	attempt := 0

	for time.Now().Before(deadline) {
		data, addr, err := deviceRemote.RecvFrom(4096)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				attempt++
				if attempt <= 2 {
					t.logf("Retransmit STUN init (attempt %d)", attempt)
					deviceRemote.Send(stunInit)
				}
				continue
			}
			break
		}
		magic := data[:4]
		t.logf("STUN <<< %s magic=%x len=%d", addr, magic, len(data))

		if string(magic) == "\xFE\xFE\xFF\xE7" {
			stunResponse = data
			t.logf("Got STUN response (fefeffe7)")
			break
		} else if string(magic) == "\xFF\xFE\xFF\xE7" {
			t.logf("Got device cross-STUN init (fffeffe7), responding...")
			resp := make([]byte, 0, 40)
			resp = append(resp, []byte{0xFE, 0xFE, 0xFF, 0xE7}...)
			resp = append(resp, data[4:8]...)
			resp = append(resp, data[8:20]...)
			resp = append(resp, []byte{0x7F, 0xD6, 0xFF, 0xF7}...)
			resp = append(resp, invAid...)
			resp = append(resp, []byte{0xFF, 0xFB, 0xFF, 0xF7, 0xFF, 0xFE}...)
			resp = append(resp, data[34:40]...)
			deviceRemote.SendTo(resp, addr)
			t.logf("STUN >>> %s response sent", addr)
		} else {
			t.logf("Unknown magic: %x", magic)
		}
	}

	if stunResponse == nil {
		t.logf("STUN failed — using relay agent as the data path")
		t.statusf(PhasePTCPHandshake, "relay path")
		t.primary = mainRemote
		return nil
	}

	// Confirm the direct channel with a burst of 5 Binding Confirms.
	t.statusf(PhasePTCPHandshake, "PTCP handshake")
	confirm := []byte{0xFE, 0xFE, 0xFF, 0xF3}
	confirm = append(confirm, cookie...)
	confirm = append(confirm, transID...)
	confirm = append(confirm, []byte{0x7F, 0xD6, 0xFF, 0xF7}...)
	confirm = append(confirm, invAid...)

	for range 5 {
		t.logf("Confirm >>>")
		deviceRemote.Send(confirm)
	}

	time.Sleep(300 * time.Millisecond)
	deviceRemote.SetTimeout(500 * time.Millisecond)
	for {
		data, addr, err := deviceRemote.RecvFrom(4096)
		if err != nil {
			break
		}
		t.logf("Drain <<< %s magic=%x len=%d", addr, data[:4], len(data))
	}
	deviceRemote.SetTimeout(0)

	// Direct path: full PTCP auth handshake with the sign token.
	if err := ptcpHandshake(deviceRemote, sign); err != nil {
		return fmt.Errorf("ptcp device handshake: %v", err)
	}
	t.logf("PTCP handshake complete (direct)")
	t.primary = deviceRemote
	return nil
}

// attachTCPRelay dials the relay agent over TCP and installs the TOU
// channel as the active data path (docs/REVERSE.md §14-16).
func (t *Tunnel) attachTCPRelay(agentHost string, agentPort int, token string) error {
	ch, err := dialTCPRelay(agentHost, agentPort, token, t.debug, t.logf)
	if err != nil {
		return err
	}
	t.socksMu.Lock()
	t.tou = ch
	t.useTCPPath = true
	t.socksMu.Unlock()
	return nil
}

// ptcpHandshake runs SYNC -> AUTH_REQ(0x19+sign) -> AUTH_RESP(0x1A) ->
// AUTH_FINAL(0x1B) against the peer on socket u.
func ptcpHandshake(u *UDP, signToken []byte) error {
	u.RequestPTCP([]byte{0x00, 0x03, 0x01, 0x00})
	u.logf("waiting for ptcp sync (timeout %.0fs)", RELAY_READ_TIMEOUT.Seconds())
	p, err := u.ReadPTCP(RELAY_READ_TIMEOUT)
	if err != nil {
		return err
	}
	if string(p.Body) != "\x00\x03\x01\x00" {
		return fmt.Errorf("ptcp sync mismatch")
	}

	pkt := append([]byte{0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, signToken...)
	u.RequestPTCP(pkt)
	u.logf("waiting for ptcp auth (timeout %.0fs)", RELAY_READ_TIMEOUT.Seconds())
	p, err = u.ReadPTCP(RELAY_READ_TIMEOUT)
	if err != nil {
		return err
	}
	for len(p.Body) == 0 {
		u.logf("waiting for ptcp auth body (timeout %.0fs)", RELAY_READ_TIMEOUT.Seconds())
		p, err = u.ReadPTCP(RELAY_READ_TIMEOUT)
		if err != nil {
			return err
		}
	}
	if p.Body[0] != 0x1A {
		return fmt.Errorf("ptcp auth mismatch: got 0x%02x", p.Body[0])
	}

	u.RequestPTCP([]byte{0x1B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	u.logf("waiting for ptcp final (timeout %.0fs)", RELAY_READ_TIMEOUT.Seconds())
	p, err = u.ReadPTCP(RELAY_READ_TIMEOUT)
	if err != nil {
		return err
	}
	if len(p.Body) != 0 {
		return fmt.Errorf("ptcp final expected empty")
	}
	return nil
}

// serve opens the local listeners and pumps traffic until the tunnel dies.
func (t *Tunnel) serve() error {
	type okListen struct {
		idx    int
		port   int
		remote int
	}
	oks := []okListen{}
	for i, spec := range t.specs {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", spec.Local))
		if err != nil {
			t.logf("listen :%d failed: %v", spec.Local, err)
			if t.reg != nil {
				t.reg.fail(t.specIdx[i], fmt.Sprintf("listen :%d: %v", spec.Local, err))
			}
			continue
		}
		port := spec.Local
		if port == 0 {
			if addr, ok := ln.Addr().(*net.TCPAddr); ok {
				port = addr.Port
			}
		}
		t.listeners = append(t.listeners, ln)
		oks = append(oks, okListen{idx: t.specIdx[i], port: port, remote: spec.Remote})
		go t.acceptLoop(ln, spec.Remote)
	}
	if len(t.listeners) == 0 {
		return fmt.Errorf("no listeners available for tunnel")
	}

	for _, o := range oks {
		if t.reg != nil {
			t.reg.okPort(o.idx, o.port)
		}
	}
	if t.progress != nil {
		// Single-mode: overwrite the progress bar line with the final "Listening" message.
		o := oks[0]
		t.progress.Done(fmt.Sprintf("Listening on :%d → :%d", o.port, o.remote))
	} else if t.ui == nil {
		for _, o := range oks {
			fmt.Printf("Listening on port %d, remote port %d\n", o.port, o.remote)
		}
	}

	t.primary.lastRecv = time.Now()

	done := t.done
	if t.useTCPPath {
		t.readerWG.Add(2)
		go t.touReadLoop(done)
		go t.touHeartbeatLoop(done)
	} else {
		t.readerWG.Add(3)
		go t.readLoop(done, t.deviceRemote)
		go t.readLoop(done, t.mainRemote)
		go t.heartbeatLoop(done)
		// Realm pool keepers: maintain pre-bound realms per forwarded port
		// so browser connection waves never pay the BIND round-trip.
		t.readerWG.Add(len(oks))
		for _, o := range oks {
			t.poolMu.Lock()
			t.pools[o.remote] = &poolState{}
			t.poolMu.Unlock()
			go t.poolKeeper(done, o.remote)
		}
	}

	for {
		select {
		case <-t.done:
			t.readerWG.Wait()
			return t.failure()
		case ac := <-t.acceptCh:
			go t.handleBind(ac)
		}
	}
}

// readLoop consumes PTCP frames from one socket. done is the generation
// token captured at spawn: after a reset this goroutine must exit silently.
func (t *Tunnel) readLoop(done chan struct{}, u *UDP) {
	defer t.readerWG.Done()
	for {
		select {
		case <-done:
			return
		default:
		}

		p, err := u.ReadPTCP(5 * time.Second)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if u == t.primary && time.Since(u.LastRecv()) > HEARTBEAT_TIMEOUT {
					t.fail(fmt.Errorf("heartbeat timeout: no PTCP on primary socket for %v", HEARTBEAT_TIMEOUT))
					return
				}
				continue
			}
			select {
			case <-done:
			default:
				t.fail(err)
			}
			return
		}
		t.routePTCP(p, u)
	}
}

// touReadLoop consumes TOU frames from the TCP relay channel.
func (t *Tunnel) touReadLoop(done chan struct{}) {
	defer t.readerWG.Done()
	t.socksMu.Lock()
	ch := t.tou
	t.socksMu.Unlock()
	if ch == nil {
		return
	}
	for {
		select {
		case <-done:
			return
		default:
		}
		typ, session, payload, _, err := ch.readFrame(time.Now().Add(tcpRelayFrameTimeout))
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if time.Since(ch.LastRecv()) > HEARTBEAT_TIMEOUT {
					t.fail(fmt.Errorf("tcp relay heartbeat timeout: no TOU frames for %v", HEARTBEAT_TIMEOUT))
					return
				}
				continue
			}
			select {
			case <-done:
			default:
				t.fail(err)
			}
			return
		}
		switch typ {
		case touTypeData:
			if c := t.getClient(session); c != nil && len(payload) > 0 {
				c.writeData(payload)
			}
		case touTypeSyn:
			// Remote session open — acknowledge per TOU convention.
			ch.writeAck(session, 0)
			t.logf("tcp-relay: remote SYN session=%#010x, ACK sent", session)
		case touTypeAck, touTypeKA, touTypeSrv:
			// liveness handled via LastRecv
		default:
			t.logf("tcp-relay: frame type=0x%02x (ignored)", typ)
		}
	}
}

// touHeartbeatLoop keeps the TCP relay channel and client sessions alive.
func (t *Tunnel) touHeartbeatLoop(done chan struct{}) {
	defer t.readerWG.Done()
	hb := time.NewTicker(tcpRelayKeepaliveEvery)
	defer hb.Stop()
	for {
		select {
		case <-done:
			return
		case <-hb.C:
			t.socksMu.Lock()
			ch := t.tou
			t.socksMu.Unlock()
			if ch == nil {
				return
			}
			if err := ch.writeKeepalive(0); err != nil {
				t.fail(fmt.Errorf("tcp relay keepalive: %v", err))
				return
			}
			now := time.Now()
			t.clientsMu.Lock()
			for rid, c := range t.clients {
				if now.Sub(c.lastKeepalive) > 25*time.Second && c.remotePort == 554 {
					ka := fmt.Sprintf("OPTIONS * RTSP/1.0\r\nCSeq: %d\r\n\r\n", c.cseq)
					t.writeRealmData(rid, []byte(ka))
					c.cseq++
					c.lastKeepalive = now
				}
			}
			t.clientsMu.Unlock()
		}
	}
}

func (t *Tunnel) heartbeatLoop(done chan struct{}) {
	defer t.readerWG.Done()
	hb := time.NewTicker(5 * time.Second)
	defer hb.Stop()
	for {
		select {
		case <-done:
			return
		case <-hb.C:
			t.socksMu.Lock()
			mr := t.mainRemote
			t.socksMu.Unlock()
			if mr != nil {
				mr.RequestPTCP([]byte{})
			}
			if t.primary != nil {
				t.primary.RequestPTCP(ptcpHeartbeat)
			}

			now := time.Now()
			t.clientsMu.Lock()
			for rid, c := range t.clients {
				// Inject keepalive bytes only into RTSP realms: OPTIONS
				// would be protocol garbage inside DVRIP (37777) or HTTP
				// (80) streams. PTCP heartbeats keep the tunnel itself up.
				if now.Sub(c.lastKeepalive) > 25*time.Second && c.remotePort == 554 {
					ka := fmt.Sprintf("OPTIONS * RTSP/1.0\r\nCSeq: %d\r\n\r\n", c.cseq)
					t.writeRealmData(rid, []byte(ka))
					c.cseq++
					c.lastKeepalive = now
				}
			}
			t.clientsMu.Unlock()
		}
	}
}

func (t *Tunnel) acceptLoop(ln net.Listener, remotePort int) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		select {
		case t.acceptCh <- acceptConn{conn: conn, remotePort: remotePort}:
		case <-t.done:
			conn.Close()
			return
		}
	}
}

// popRealm takes a pre-bound realm for the remote port if available.
func (t *Tunnel) popRealm(remotePort int) (uint32, bool) {
	t.poolMu.Lock()
	defer t.poolMu.Unlock()
	st := t.pools[remotePort]
	if st == nil || len(st.queue) == 0 {
		return 0, false
	}
	r := st.queue[0]
	st.queue = st.queue[1:]
	return r, true
}

func (t *Tunnel) pushRealm(remotePort int, realm uint32) {
	t.poolMu.Lock()
	defer t.poolMu.Unlock()
	st := t.pools[remotePort]
	if st == nil || len(st.queue) >= t.poolTarget {
		return
	}
	st.queue = append(st.queue, realm)
}

// dropRealm removes a realm from the pool (device discarded it).
func (t *Tunnel) dropRealm(realm uint32) {
	t.poolMu.Lock()
	defer t.poolMu.Unlock()
	for _, st := range t.pools {
		for i, r := range st.queue {
			if r == realm {
				st.queue = append(st.queue[:i], st.queue[i+1:]...)
				return
			}
		}
	}
}

// preBindRealm opens one realm and parks it in the pool.
func (t *Tunnel) preBindRealm(remotePort int) {
	t.poolMu.Lock()
	st := t.pools[remotePort]
	if st == nil || t.poolTarget <= 0 ||
		len(st.queue)+st.inflight >= t.poolTarget {
		t.poolMu.Unlock()
		return
	}
	st.inflight++
	t.poolMu.Unlock()

	defer func() {
		t.poolMu.Lock()
		st.inflight--
		t.poolMu.Unlock()
	}()

	realmID := rand.Uint32()
	wait := make(chan struct{})
	t.setBindWait(realmID, wait)

	bindPkt := make([]byte, 20)
	bindPkt[0] = 0x11
	binary.BigEndian.PutUint32(bindPkt[4:8], realmID)
	binary.BigEndian.PutUint32(bindPkt[12:16], uint32(remotePort))
	bindPkt[16] = 0x7F
	bindPkt[19] = 0x01
	t.bindReqMu.Lock()
	t.primary.RequestPTCP(bindPkt)
	time.Sleep(3 * time.Millisecond)
	t.bindReqMu.Unlock()

	select {
	case <-wait:
		t.pushRealm(remotePort, realmID)
		t.logf("Realm pool: pre-bound realm=%#010x port=%d", realmID, remotePort)
	case <-time.After(BIND_TIMEOUT):
		t.takeBindWait(realmID)
	case <-t.done:
		t.takeBindWait(realmID)
	}
}

// poolKeeper maintains the fixed pre-bound realm level for one remote port.
func (t *Tunnel) poolKeeper(done chan struct{}, remotePort int) {
	defer t.readerWG.Done()
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-done:
			return
		case <-tick.C:
			t.poolMu.Lock()
			st := t.pools[remotePort]
			if st == nil {
				t.poolMu.Unlock()
				return
			}
			spawn := t.poolTarget - len(st.queue) - st.inflight
			if spawn < 0 {
				spawn = 0
			}
			t.poolMu.Unlock()
			for i := 0; i < spawn; i++ {
				go t.preBindRealm(remotePort)
			}
		}
	}
}

// handleBind opens one realm: random realm id, BIND frame, wait for STATUS OK.
// In TCP-relay mode the realm is a TOU session opened with a SYN frame.
// On the UDP path a pooled pre-bound realm is preferred: no BIND wait.
func (t *Tunnel) handleBind(ac acceptConn) {
	if !t.useTCPPath {
		if realmID, ok := t.popRealm(ac.remotePort); ok {
			t.logf("Realm pool: hit realm=%#010x port=%d", realmID, ac.remotePort)
			t.addClient(realmID, ac.conn, ac.remotePort)
			return
		}
	}

	realmID := rand.Uint32()
	t.logf("Binding realm=%#010x port=%d", realmID, ac.remotePort)

	if t.useTCPPath {
		t.addClient(realmID, ac.conn, ac.remotePort)
		t.socksMu.Lock()
		ch := t.tou
		t.socksMu.Unlock()
		if ch == nil {
			ac.conn.Close()
			t.delClient(realmID)
			return
		}
		if err := ch.write(touBuildSyn(realmID)); err != nil {
			t.logf("tcp-relay SYN failed realm=%#010x: %v", realmID, err)
			t.delClient(realmID)
			ac.conn.Close()
			return
		}
		t.logf("tcp-relay: SYN sent for session=%#010x (port %d)", realmID, ac.remotePort)
		return
	}

	wait := make(chan struct{})
	t.setBindWait(realmID, wait)

	t.addClient(realmID, ac.conn, ac.remotePort)

	bindPkt := make([]byte, 20)
	bindPkt[0] = 0x11
	binary.BigEndian.PutUint32(bindPkt[4:8], realmID)
	binary.BigEndian.PutUint32(bindPkt[12:16], uint32(ac.remotePort))
	bindPkt[16] = 0x7F
	bindPkt[19] = 0x01
	bindStart := time.Now()
	t.bindReqMu.Lock()
	t.primary.RequestPTCP(bindPkt)
	time.Sleep(10 * time.Millisecond)
	t.bindReqMu.Unlock()

	select {
	case <-wait:
		t.logf("Bind OK realm=%#010x in %v", realmID, time.Since(bindStart))
	case <-time.After(BIND_TIMEOUT):
		t.logf("Bind FAILED realm=%#010x port=%d", realmID, ac.remotePort)
		t.delClient(realmID)
		ac.conn.Close()
		t.takeBindWait(realmID)
	case <-t.done:
		t.takeBindWait(realmID)
		ac.conn.Close()
	}
}

func (t *Tunnel) setBindWait(realmID uint32, ch chan struct{}) {
	t.bindMu.Lock()
	t.bindWait[realmID] = ch
	t.bindMu.Unlock()
}

func (t *Tunnel) takeBindWait(realmID uint32) chan struct{} {
	t.bindMu.Lock()
	defer t.bindMu.Unlock()
	ch := t.bindWait[realmID]
	delete(t.bindWait, realmID)
	return ch
}

func (t *Tunnel) addClient(realmID uint32, conn net.Conn, remotePort int) {
	t.clientsMu.Lock()
	t.clients[realmID] = &Client{
		conn:          conn,
		lastKeepalive: time.Now(),
		cseq:          t.cseqCounter,
		remotePort:    remotePort,
	}
	t.cseqCounter += CSEQ_STEP
	active := len(t.clients)
	t.clientsMu.Unlock()
	t.logf("Client realm=%#010x, %d active", realmID, active)
	go t.clientReader(conn, realmID)
}

func (t *Tunnel) getClient(realmID uint32) *Client {
	t.clientsMu.Lock()
	defer t.clientsMu.Unlock()
	return t.clients[realmID]
}

func (t *Tunnel) delClient(realmID uint32) {
	t.clientsMu.Lock()
	delete(t.clients, realmID)
	t.clientsMu.Unlock()
}

// dataSegmentMax matches the device's own segmentation observed in the
// capture (1316-byte datagrams = 1280-byte DATA payloads): sending larger
// frames triggers IP fragmentation and raises loss probability.
const dataSegmentMax = 1280

// writeRealmData pushes one realm payload down the active data path,
// segmented to wire-safe sizes.
func (t *Tunnel) writeRealmData(realm uint32, data []byte) {
	for len(data) > 0 {
		n := len(data)
		if n > dataSegmentMax {
			n = dataSegmentMax
		}
		chunk := data[:n]
		if t.useTCPPath {
			t.socksMu.Lock()
			ch := t.tou
			t.socksMu.Unlock()
			if ch == nil {
				return
			}
			ch.writeData(realm, chunk)
		} else if t.primary != nil {
			t.primary.RequestPTCP((&PTCPPayload{Realm: realm, Payload: chunk}).Bytes())
		}
		data = data[n:]
	}
}

// clientReader pumps local TCP bytes into the tunnel as realm DATA.
func (t *Tunnel) clientReader(conn net.Conn, realmID uint32) {
	buf := make([]byte, 16*1024)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if !t.useTCPPath {
				discPkt := make([]byte, 16)
				discPkt[0] = 0x12
				binary.BigEndian.PutUint32(discPkt[4:8], realmID)
				copy(discPkt[12:], "DISC")
				t.primary.RequestPTCP(discPkt)
			}
			t.logf("Disconnected realm=%#010x", realmID)
			t.delClient(realmID)
			return
		}
		t.writeRealmData(realmID, buf[:n])
	}
}

// routePTCP dispatches one inbound PTCP frame. Empty bodies are the peer's
// pure ACKs — mirror them. Data frames get a coalesced ack (ScheduleAck).
func (t *Tunnel) routePTCP(p *PTCP, src *UDP) {
	if len(p.Body) == 0 {
		src.RequestPTCP(nil)
		return
	}
	src.ScheduleAck()

	switch p.Body[0] {
	case 0x10:
		pl, err := ParsePTCPPayload(p.Body)
		if err != nil {
			return
		}
		if c := t.getClient(pl.Realm); c != nil {
			if c := t.getClient(pl.Realm); c != nil && len(pl.Payload) > 0 {
				c.writeData(pl.Payload)
			}
		}
	case 0x12:
		realm := binary.BigEndian.Uint32(p.Body[4:8])
		if ch := t.takeBindWait(realm); ch != nil {
			close(ch)
			return
		}
		t.dropRealm(realm) // device discarded a pooled realm
		if c := t.getClient(realm); c != nil {
			c.conn.Close()
			t.delClient(realm)
			t.logf("DVR DISC realm=%#010x", realm)
		}
	case 0x13:
		// Peer heartbeat — liveness is tracked via lastRecv.
	case 0x0a:
		// Flow-control / ping frame from device or relay agent; no-op.
	default:
		var sincePrimary float64
		if t.primary != nil {
			sincePrimary = time.Since(t.primary.LastRecv()).Seconds()
		}
		srcStr := "secondary"
		if src == t.primary {
			srcStr = "primary"
		}
		t.logf("PTCP type=%#04x len=%d src=%s sincePrimary=%.2fs time=%s hex=%x",
			p.Body[0], len(p.Body), srcStr, sincePrimary, time.Now().Format("15:04:05.000"), p.Body)
		if len(p.Body) >= 12 {
			tryRealm := binary.BigEndian.Uint32(p.Body[4:8])
			payload := p.Body[12:]
			if len(payload) > 0 && len(payload) <= 4096 {
				if c := t.getClient(tryRealm); c != nil {
					t.logf("Forwarding type 0x%02x as data to realm=%#010x (%d bytes)", p.Body[0], tryRealm, len(payload))
					c.writeData(payload)
				}
			}
		}
	}
}

func (t *Tunnel) fail(err error) {
	t.errMu.Lock()
	if t.failErr == nil {
		t.failErr = err
	}
	t.errMu.Unlock()
	select {
	case <-t.done:
	default:
		close(t.done)
	}
}

func (t *Tunnel) failure() error {
	t.errMu.Lock()
	defer t.errMu.Unlock()
	return t.failErr
}

func runWithRetries(t *Tunnel, cp *ConnectProgress, onExhausted func(err error)) {
	for attempt := 1; ; attempt++ {
		if cp != nil {
			cp.SetAttempt(attempt)
			t.progress = cp
		}
		attemptStart := time.Now()
		err := t.Run()
		if err == nil {
			// cp.Done() was already called from serve() when listeners came up.
			return
		}
		duration := time.Since(attemptStart)
		if errors.Is(err, errDeviceNotFound) {
			deviceNotFound(t.serial)
			if t.reg != nil {
				for _, idx := range t.specIdx {
					t.reg.fail(idx, err.Error())
				}
			}
			if cp != nil {
				cp.Fail("device not found")
			}
			if onExhausted != nil {
				onExhausted(err)
			}
			return
		}
		if attempt > RETRY_ATTEMPTS {
			if t.reg != nil {
				for _, idx := range t.specIdx {
					t.reg.fail(idx, err.Error())
				}
			}
			if cp != nil {
				cp.Fail(err.Error())
			}
			if onExhausted != nil {
				onExhausted(err)
			}
			return
		}
		t.markConnecting()
		msg := fmt.Sprintf("Tunnel failed after %.1fs, reason - %v, retrying %d/%d", duration.Seconds(), err, attempt, RETRY_ATTEMPTS)
		if cp != nil {
			// Reset the bar to 0% for the next attempt, keep the error visible briefly.
			cp.Reset(fmt.Sprintf("retry %d/%d: %s", attempt+1, RETRY_ATTEMPTS, err.Error()))
		} else if t.ui != nil {
			t.ui.Below(msg)
		} else {
			fmt.Println(msg)
		}
		if t.logRetries {
			detail := fmt.Sprintf("[%s] tunnel retry %d/%d: %v", time.Now().Format(time.RFC3339), attempt, RETRY_ATTEMPTS, err)
			if t.ui != nil {
				t.ui.Below(detail)
			} else {
				fmt.Println(detail)
			}
		}
		time.Sleep(RETRY_DELAY)
		t.reset()
	}
}

// queryDeviceInfo fetches /info/device/<SN> from the device's P2P server and
// decrypts the "Info" blob with the hardcoded SDK keys (docs/REVERSE.md
// 4.2), recovering randsalt / devP2PVersion for Type 1 auth.
func queryDeviceInfo(serial string, debug bool) int {
	u := NewUDP(MAIN_SERVER, MAIN_PORT, debug)
	defer u.Close()
	if u.initErr != nil {
		fmt.Fprintf(os.Stderr, "main socket: %v\n", u.initErr)
		return 1
	}
	u.Request("/probe/p2psrv", "", true, true)
	res, _ := u.Request(fmt.Sprintf("/online/p2psrv/%s", serial), "", true, true)
	if res == nil || res.Code >= 400 || res.Body["body/US"] == "" {
		fmt.Printf("%s doesn't exist or turned off.\n", serial)
		return 1
	}
	us := strings.SplitN(res.Body["body/US"], ":", 2)
	usPort, _ := strconv.Atoi(us[1])

	v := NewUDP(us[0], usPort, debug)
	defer v.Close()
	if v.initErr != nil {
		fmt.Fprintf(os.Stderr, "device socket: %v\n", v.initErr)
		return 1
	}
	v.Request(fmt.Sprintf("/probe/device/%s", serial), "", true, true)
	v.Request(fmt.Sprintf("/info/device/%s", serial), "", true, false)

	data, err := v.Recv(65536, RELAY_READ_TIMEOUT)
	if err != nil {
		fmt.Fprintf(os.Stderr, "info read: %v\n", err)
		return 1
	}
	text := strings.TrimSpace(string(data))
	if debug {
		fmt.Println(text)
	}

	fields := map[string]string{}
	if strings.HasPrefix(text, "{") {
		if err := json.Unmarshal([]byte(text), &fields); err != nil {
			fmt.Fprintf(os.Stderr, "json parse: %v\n", err)
			return 1
		}
	} else {
		resp := ParseDHResponse(text)
		for k, val := range resp.Body {
			fields[strings.TrimPrefix(k, "body/")] = val
		}
	}

	if v2 := fields["devp2pver"]; v2 != "" {
		fmt.Printf("devP2PVersion : %s\n", v2)
	}
	if dv := fields["DevVersion"]; dv != "" {
		fmt.Printf("DevVersion    : %s\n", dv)
	}

	info := fields["Info"]
	if info == "" {
		fmt.Println("Info field   : (absent — device provided no encrypted blob)")
		return 0
	}
	plain, err := decryptDevInfoInfo(info)
	if err != nil {
		fmt.Fprintf(os.Stderr, "decrypt Info: %v\n", err)
		return 1
	}
	if !isMostlyPrintable(plain) {
		fmt.Fprintf(os.Stderr, "decrypt Info: result is not printable, raw: %x\n", plain)
		return 1
	}
	fmt.Println("Info (plain) :")
	inner := map[string]string{}
	if json.Unmarshal(plain, &inner) == nil {
		keys := make([]string, 0, len(inner))
		for k := range inner {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("  %-16s = %s\n", k, inner[k])
		}
		if inner["randsalt"] != "" {
			fmt.Printf("\nUse: dh-fwd %s -t 1 -u <user> -P <pass> -s %s\n", serial, inner["randsalt"])
		}
	} else {
		fmt.Println(string(plain))
	}
	return 0
}

func isMostlyPrintable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	ok := 0
	for _, c := range b {
		if (c >= 0x20 && c < 0x7F) || c == '\n' || c == '\r' || c == '\t' {
			ok++
		}
	}
	return ok*100/len(b) > 90
}
