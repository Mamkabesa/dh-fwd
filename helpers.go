package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// Cloud endpoints and stock client credentials (public, embedded in every
// official Dahua client: SmartPSS, DMSS, gDMSS).
const (
	MAIN_SERVER = "www.easy4ipcloud.com"
	MAIN_PORT   = 8800

	WSSE_USERNAME = "cba1b29e32cb17aa46b8ff9e73c7f40b"
	WSSE_USERKEY  = "996103384cdf19179e19243e959bbf8b"
	DEFAULT_SALT  = ""
	AES_IV        = "2z52*lk9o6HRyJrf"
)

var (
	cseqLock sync.Mutex
	cseq     uint32
)

// ---------------------------------------------------------------------------
// Device auth (Type 1): master key derivation, AES-OFB address encryption,
// HMAC-SHA256 request signing. Mirrors section 4.3 of the DH-P2P spec.
// ---------------------------------------------------------------------------

// getDeriveKey builds the 32-char uppercase-hex MD5 master key:
//   MD5(user + ":Login to " + salt + ":" + pass), rendered as ASCII hex.
func getDeriveKey(username, password, randsalt string) []byte {
	salt := randsalt
	if salt == "" {
		salt = DEFAULT_SALT
	}
	sum := md5.Sum([]byte(fmt.Sprintf("%s:Login to %s:%s", username, salt, password)))
	return []byte(fmt.Sprintf("%X", sum))
}

// getNonce returns a random int32 for the PBKDF2 salt.
func getNonce() int {
	n, _ := rand.Int(rand.Reader, big.NewInt(1<<31))
	return int(n.Int64())
}

// deriveDK expands the master key: PBKDF2-HMAC-SHA256(key, decimal(nonce), 20000, 32).
func deriveDK(key []byte, nonce int) []byte {
	salt := []byte(strconv.Itoa(nonce))
	return pbkdf2.Key(key, salt, 20000, 32, sha256.New)
}

// getEnc encrypts LocalAddr with AES-128-OFB over the derived key and the
// fixed IV, returning Base64. Section 4.3 step 3 of the spec.
func getEnc(key []byte, nonce int, data string) string {
	dk := deriveDK(key, nonce)
	block, _ := aes.NewCipher(dk)
	stream := cipher.NewOFB(block, []byte(AES_IV))
	out := make([]byte, len(data))
	stream.XORKeyStream(out, []byte(data))
	return base64.StdEncoding.EncodeToString(out)
}

// getDec reverses getEnc: decrypts the device's encrypted LocalAddr.
func getDec(key []byte, nonce int, data string) string {
	dk := deriveDK(key, nonce)
	block, _ := aes.NewCipher(dk)
	stream := cipher.NewOFB(block, []byte(AES_IV))
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return data
	}
	out := make([]byte, len(raw))
	stream.XORKeyStream(out, raw)
	return string(out)
}

// getAuth builds the DevAuth XML block: Base64(HMAC-SHA256(masterKey,
// string(nonce) + string(unixNow) + payload)). Section 4.3 step 4.
func getAuth(username string, key []byte, nonce int, payload, randsalt string) string {
	salt := randsalt
	if salt == "" {
		salt = DEFAULT_SALT
	}
	curdate := time.Now().Unix()
	msg := []byte(fmt.Sprintf("%d%d%s", nonce, curdate, payload))
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	auth := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf(
		"<CreateDate>%d</CreateDate><DevAuth>%s</DevAuth><Nonce>%d</Nonce><RandSalt>%s</RandSalt><UserName>%s</UserName>",
		curdate, auth, nonce, salt, username,
	)
}

// Hardcoded devinfo crypto recovered from P2PDll.dll
// (CP2PClientImpl::parseDeviceInfo, see docs/REVERSE.md section 4.2):
// the "Info" field of /info/device/<SN> is Base64(AES-256-OFB(JSON)).
const (
	DEVINFO_KEY = "kRjmsUB&ezmdGLL67H#$ojw@XflcaIaf" // 32 bytes, AES-256
	DEVINFO_IV  = "MydvJw*Iw1w&i^kk"                 // 16 bytes IV
)

// decryptDevInfoInfo decrypts the base64 AES-256-OFB "Info" field.
func decryptDevInfoInfo(field string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(field))
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher([]byte(DEVINFO_KEY))
	if err != nil {
		return nil, err
	}
	stream := cipher.NewOFB(block, []byte(DEVINFO_IV))
	out := make([]byte, len(raw))
	stream.XORKeyStream(out, raw)
	return out, nil
}

// ---------------------------------------------------------------------------
// PTCP wire format (Level 3). 24-byte big-endian header:
// "PTCP" | Rlid | Llid | Pid | Lmid | Rmid, then body.
// ---------------------------------------------------------------------------

// PTCPPayload is a realm-multiplexed DATA fragment (body type 0x10).
type PTCPPayload struct {
	Realm   uint32
	Payload []byte
}

func (p *PTCPPayload) Bytes() []byte {
	length := len(p.Payload) | 0x10000000
	buf := make([]byte, 12+len(p.Payload))
	binary.BigEndian.PutUint32(buf[0:4], uint32(length))
	binary.BigEndian.PutUint32(buf[4:8], p.Realm)
	binary.BigEndian.PutUint32(buf[8:12], 0)
	copy(buf[12:], p.Payload)
	return buf
}

func ParsePTCPPayload(data []byte) (*PTCPPayload, error) {
	if len(data) < 12 {
		return nil, errors.New("packet too short")
	}
	length := binary.BigEndian.Uint32(data[0:4])
	realm := binary.BigEndian.Uint32(data[4:8])
	pad := binary.BigEndian.Uint32(data[8:12])
	if pad != 0 {
		return nil, errors.New("invalid padding")
	}
	length &= 0xFFFF
	body := data[12:]
	if len(body) != int(length) {
		return nil, errors.New("invalid length")
	}
	return &PTCPPayload{Realm: realm, Payload: body}, nil
}

// PTCP is a full transport frame.
type PTCP struct {
	Rlid uint32 // remote bytes-sent ack
	Llid uint32 // local bytes-received ack
	Pid  uint32 // package id (SYNC marker or 0x0000FFFF - count)
	Lmid uint32 // local message counter
	Rmid uint32 // echo of peer Lmid
	Body []byte
}

func (p *PTCP) Bytes() []byte {
	buf := make([]byte, 24+len(p.Body))
	copy(buf[0:4], "PTCP")
	binary.BigEndian.PutUint32(buf[4:8], p.Rlid)
	binary.BigEndian.PutUint32(buf[8:12], p.Llid)
	binary.BigEndian.PutUint32(buf[12:16], p.Pid)
	binary.BigEndian.PutUint32(buf[16:20], p.Lmid)
	binary.BigEndian.PutUint32(buf[20:24], p.Rmid)
	copy(buf[24:], p.Body)
	return buf
}

func ParsePTCP(data []byte) (*PTCP, error) {
	if len(data) < 24 {
		return nil, errors.New("packet too short")
	}
	if string(data[0:4]) != "PTCP" {
		return nil, errors.New("invalid magic")
	}
	return &PTCP{
		Rlid: binary.BigEndian.Uint32(data[4:8]),
		Llid: binary.BigEndian.Uint32(data[8:12]),
		Pid:  binary.BigEndian.Uint32(data[12:16]),
		Lmid: binary.BigEndian.Uint32(data[16:20]),
		Rmid: binary.BigEndian.Uint32(data[20:24]),
		Body: data[24:],
	}, nil
}

// ---------------------------------------------------------------------------
// DH HTTP-over-UDP (Level 1) response parsing.
// ---------------------------------------------------------------------------

type DHResponse struct {
	Version string
	Code    int
	Status  string
	Headers map[string]string
	Body    map[string]string
}

func ParseDHResponse(data string) *DHResponse {
	parts := strings.SplitN(data, "\r\n\r\n", 2)
	headPart := parts[0]
	bodyPart := ""
	if len(parts) > 1 {
		bodyPart = strings.TrimSpace(parts[1])
	}

	lines := strings.Split(headPart, "\r\n")
	statusParts := strings.SplitN(lines[0], " ", 3)
	code, _ := strconv.Atoi(statusParts[1])

	headers := make(map[string]string)
	for _, line := range lines[1:] {
		if hd := strings.SplitN(line, ": ", 2); len(hd) == 2 {
			headers[hd[0]] = hd[1]
		}
	}

	resp := &DHResponse{
		Version: statusParts[0],
		Code:    code,
		Status:  strings.Join(statusParts[2:], " "),
		Headers: headers,
	}
	if bodyPart != "" {
		resp.Body = parseXML(bodyPart)
	}
	return resp
}

// parseXML flattens a <body> XML document into "path/to/tag" -> text.
func parseXML(data string) map[string]string {
	result := make(map[string]string)
	decoder := xml.NewDecoder(strings.NewReader(data))
	var stack []string

	for {
		tok, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		switch t := tok.(type) {
		case xml.StartElement:
			stack = append(stack, t.Name.Local)
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			text := strings.TrimSpace(string(t))
			if text != "" && len(stack) > 0 {
				result[strings.Join(stack, "/")] = text
			}
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// UDP socket wrapper. Every socket in the program is created through NewUDP:
// it forces udp4 and disables SIO_UDP_CONNRESET on Windows (without it a past
// ICMP port-unreachable poisons the next read with WSAECONNRESET).
// ---------------------------------------------------------------------------

type UDP struct {
	conn *net.UDPConn

	initErr error

	lhost string
	lport int

	rhost string
	rport int

	raddr *net.UDPAddr
	debug bool

	ptcpMu    sync.Mutex
	ptcpSent  uint32
	ptcpRecv  uint32
	ptcpCount uint32
	ptcpID    uint32
	rmid      uint32

	ackFrames uint32
	lastAck   time.Time

	rxMu     sync.Mutex
	rxBuf    []byte // reusable receive buffer (single reader per socket)
	deadline time.Time

	lastRecv time.Time
	debugLog func(format string, args ...any)
}

const udpRxMax = 65535

var udpListenCfg = net.ListenConfig{Control: udpControl}

func NewUDP(host string, port int, debug bool) *UDP {
	u := &UDP{rhost: host, rport: port, debug: debug, rxBuf: make([]byte, udpRxMax)}
	pc, err := udpListenCfg.ListenPacket(context.Background(), "udp4", "0.0.0.0:0")
	if err != nil {
		u.initErr = err
		return u
	}
	conn := pc.(*net.UDPConn)
	local := conn.LocalAddr().(*net.UDPAddr)

	// Deep receive/send rings: the camera streams ~1280-byte segments at
	// wire rate; a small kernel buffer overflows on scheduler bursts and
	// the device's RTO retransmits collapse throughput.
	_ = conn.SetReadBuffer(4 * 1024 * 1024)
	_ = conn.SetWriteBuffer(1 * 1024 * 1024)

	u.conn = conn
	u.lhost = local.IP.String()
	u.lport = local.Port

	if host != "" {
		u.raddr, err = net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", host, port))
		if err != nil {
			u.initErr = err
		}
	}
	return u
}

func (u *UDP) String() string { return fmt.Sprintf(":%d", u.lport) }

func (u *UDP) Close() {
	if u.conn != nil {
		u.conn.Close()
	}
}

func (u *UDP) SetRemote(host string, port int) {
	u.rhost = host
	u.rport = port
	u.raddr, _ = net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", host, port))
}

func (u *UDP) Send(data []byte) {
	if u.conn != nil && u.raddr != nil {
		u.conn.WriteTo(data, u.raddr)
	}
}

func (u *UDP) SendTo(data []byte, addr *net.UDPAddr) {
	if u.conn != nil {
		u.conn.WriteTo(data, addr)
	}
}

func (u *UDP) Recv(bufsize int, timeout time.Duration) ([]byte, error) {
	if u.conn == nil {
		if u.initErr != nil {
			return nil, u.initErr
		}
		return nil, fmt.Errorf("udp socket is not initialized")
	}

	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	u.rxMu.Lock()
	defer u.rxMu.Unlock()
	for {
		if timeout > 0 {
			u.conn.SetReadDeadline(deadline)
		} else {
			u.conn.SetReadDeadline(time.Time{})
		}
		n, _, err := u.conn.ReadFromUDP(u.rxBuf)
		if err == nil {
			u.lastRecv = time.Now()
			// Zero-copy: the returned slice aliases rxBuf and is valid until
			// the next Recv on this socket. ReadPTCP consumers process frames
			// synchronously (routePTCP), so nothing retains it. RecvFrom keeps
			// copying because the STUN handshake holds buffers across reads.
			return u.rxBuf[:n], nil
		}
		// Windows can report WSAECONNRESET on an unconnected socket after an
		// earlier send hit a closed port; treat as spurious and keep reading
		// until the deadline expires.
		if isConnReset(err) && timeout > 0 && time.Now().Before(deadline) {
			continue
		}
		return nil, err
	}
}

func (u *UDP) RecvFrom(bufsize int) ([]byte, *net.UDPAddr, error) {
	if u.conn == nil {
		return nil, nil, fmt.Errorf("udp socket is not initialized")
	}
	u.rxMu.Lock()
	defer u.rxMu.Unlock()
	if !u.deadline.IsZero() {
		_ = u.conn.SetReadDeadline(u.deadline)
	} else {
		_ = u.conn.SetReadDeadline(time.Time{})
	}
	n, addr, err := u.conn.ReadFromUDP(u.rxBuf)
	if err != nil {
		if isConnReset(err) {
			return nil, addr, err
		}
		return nil, nil, err
	}
	u.lastRecv = time.Now()
	out := make([]byte, n)
	copy(out, u.rxBuf[:n])
	return out, addr, nil
}

func (u *UDP) LastRecv() time.Time { return u.lastRecv }

func (u *UDP) logf(format string, args ...any) {
	if u.debugLog != nil {
		u.debugLog(format, args...)
		return
	}
	fmt.Printf(format+"\n", args...)
}

func (u *UDP) SetTimeout(d time.Duration) {
	if u.conn == nil {
		return
	}
	if d > 0 {
		u.deadline = time.Now().Add(d)
		_ = u.conn.SetReadDeadline(u.deadline)
	} else {
		u.deadline = time.Time{}
		_ = u.conn.SetReadDeadline(time.Time{})
	}
}

// Read waits for one DH HTTP response.
func (u *UDP) Read(returnError bool, timeout time.Duration) (*DHResponse, error) {
	data, err := u.Recv(4096, timeout)
	if err != nil {
		return nil, err
	}

	if u.debug {
		u.logf(":%d <<< %s:%d\n%s", u.lport, u.rhost, u.rport, string(data))
	}

	res := ParseDHResponse(string(data))
	if !returnError && res.Code >= 400 {
		return nil, fmt.Errorf("error %d: %s", res.Code, res.Status)
	}
	if u.debug {
		u.logf("Parsed <<< code=%d status=%s", res.Code, res.Status)
	}
	return res, nil
}

// buildDHRequest serializes one DHGET/DHPOST transaction with WSSE cloud
// auth headers (shared by the UDP transport and the TCP-relay bind).
func buildDHRequest(method, path, body string, auth bool, myCseq uint32) []byte {
	nonce, _ := rand.Int(rand.Reader, big.NewInt(1<<31))
	curdate := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	pwd := fmt.Sprintf("%d%sDHP2P:%s:%s", nonce, curdate, WSSE_USERNAME, WSSE_USERKEY)

	h := sha1.New()
	h.Write([]byte(pwd))
	digest := base64.StdEncoding.EncodeToString(h.Sum(nil))

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\nCSeq: %d\r\n", method, path, myCseq))
	if auth {
		sb.WriteString(fmt.Sprintf(
			"Authorization: WSSE profile=\"UsernameToken\"\r\nX-WSSE: UsernameToken Username=\"%s\", PasswordDigest=\"%s\", Nonce=\"%d\", Created=\"%s\"\r\n",
			WSSE_USERNAME, digest, nonce, curdate,
		))
	}
	if body != "" {
		sb.WriteString(fmt.Sprintf("Content-Type: \r\nContent-Length: %d\r\n", len(body)))
	}
	sb.WriteString(fmt.Sprintf("\r\n%s", body))
	return []byte(sb.String())
}

// Request sends one DHGET/DHPOST transaction with WSSE cloud auth.
func (u *UDP) Request(path, body string, auth, shouldRead bool) (*DHResponse, error) {
	cseqLock.Lock()
	cseq++
	myCseq := cseq
	cseqLock.Unlock()

	method := "DHGET"
	if body != "" {
		method = "DHPOST"
	}

	req := buildDHRequest(method, path, body, auth, myCseq)

	if u.debug {
		u.logf(":%d >>> %s:%d\n%s", u.lport, u.rhost, u.rport, string(req))
	}

	u.Send(req)

	if shouldRead {
		return u.Read(false, RELAY_READ_TIMEOUT)
	}
	return nil, nil
}

const (
	// Ack coalescing (TCP-style delayed ack): the camera streams thousands
	// of 1280-byte DATA frames per second; acking each one separately
	// doubles the datagram rate and eats upstream bandwidth on chatty+bulk
	// combinations. Cumulative byte-acks (Llid) make delayed acks safe.
	ackEvery = 4
	ackDelay = 10 * time.Millisecond
)

// ScheduleAck sends one pure-ACK frame per ackEvery received frames or
// ackDelay, whichever comes first. Any outgoing frame also carries the
// cumulative ack, so nothing is lost by waiting.
func (u *UDP) ScheduleAck() {
	u.ptcpMu.Lock()
	u.ackFrames++
	flush := u.ackFrames >= ackEvery || time.Since(u.lastAck) >= ackDelay
	if flush {
		u.ackFrames = 0
		u.lastAck = time.Now()
	}
	u.ptcpMu.Unlock()
	if flush {
		u.RequestPTCP(nil)
	}
}

// ReadPTCP waits for one PTCP frame and updates ack/rmid state.
func (u *UDP) ReadPTCP(timeout time.Duration) (*PTCP, error) {
	data, err := u.Recv(4096, timeout)
	if err != nil {
		return nil, err
	}
	ptcp, err := ParsePTCP(data)
	if err != nil {
		return nil, err
	}

	u.ptcpMu.Lock()
	if ptcp.Rlid+uint32(len(ptcp.Body)) > u.ptcpRecv {
		u.ptcpRecv = ptcp.Rlid + uint32(len(ptcp.Body))
	}
	u.rmid = ptcp.Lmid
	u.ptcpMu.Unlock()

	return ptcp, nil
}

// RequestPTCP serializes and sends one PTCP frame, advancing counters.
// An empty body is a pure ACK frame. The SYNC body gets the special Pid.
//
// Pid wire semantics (docs/REVERSE.md §9.2): low 16 bits = receive window we
// advertise, high 16 bits = flags (SYN=0x0002). We drain immediately, so we
// always advertise a full 64 KB window — a shrinking count-based window used
// to throttle long video sessions because the device honors flow control.
func (u *UDP) RequestPTCP(body []byte) {
	u.ptcpMu.Lock()
	defer u.ptcpMu.Unlock()

	isSync := len(body) == 4 && body[0] == 0x00 && body[1] == 0x03 && body[2] == 0x01 && body[3] == 0x00

	pid := uint32(0x0000FFFF)
	if isSync {
		pid = 0x0002FFFF
	}

	ptcp := &PTCP{
		Rlid: u.ptcpSent,
		Llid: u.ptcpRecv,
		Pid:  pid,
		Lmid: u.ptcpID,
		Rmid: u.rmid,
		Body: body,
	}

	u.ptcpSent += uint32(len(body))
	u.ptcpID++
	if !isSync && len(body) > 0 {
		u.ptcpCount++
	}

	u.Send(ptcp.Bytes())
}

func GetInvertedBytes(data []byte) []byte {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = ^b
	}
	return out
}
