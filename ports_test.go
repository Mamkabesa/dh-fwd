package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"net"
	"testing"
	"time"
)

func TestPortParsing(t *testing.T) {
	cases := []struct {
		in      string
		want    []PortSpec
		wantErr bool
	}{
		{"8081", []PortSpec{{Local: 0, Remote: 8081}}, false},
		{"80-85", []PortSpec{{0, 80}, {0, 81}, {0, 82}, {0, 83}, {0, 84}, {0, 85}}, false},
		{"81,82,83", []PortSpec{{0, 81}, {0, 82}, {0, 83}}, false},
		{"8080:81", []PortSpec{{8080, 81}}, false},
		{"5080,5081,5082:80", []PortSpec{{5080, 80}, {5081, 80}, {5082, 80}}, false},
		{"5080,5081,5082:80,81,82", []PortSpec{{5080, 80}, {5081, 81}, {5082, 82}}, false},
		{"0:81", []PortSpec{{0, 81}}, false},
		{"8080-8082:80-82", []PortSpec{{8080, 80}, {8081, 81}, {8082, 82}}, false},
		{"8080:81,82", nil, true},
		{"80-85:0", nil, true},
		{"abc", nil, true},
	}
	for _, c := range cases {
		locals, remotes, err := parsePortLists(c.in)
		if err != nil {
			if c.wantErr {
				continue
			}
			t.Fatalf("%q: unexpected err %v", c.in, err)
		}
		specs, err := makePortSpecs(locals, remotes)
		if err != nil {
			if c.wantErr {
				continue
			}
			t.Fatalf("%q: makePortSpecs err %v", c.in, err)
		}
		if len(specs) != len(c.want) {
			t.Fatalf("%q: got %d specs, want %d", c.in, len(specs), len(c.want))
		}
		for i := range specs {
			if specs[i] != c.want[i] {
				t.Fatalf("%q: spec[%d]=%+v, want %+v", c.in, i, specs[i], c.want[i])
			}
		}
	}
}

func TestPTCPRoundtrip(t *testing.T) {
	p := &PTCP{Rlid: 1, Llid: 2, Pid: 3, Lmid: 4, Rmid: 5, Body: []byte{0xDE, 0xAD}}
	raw := p.Bytes()
	got, err := ParsePTCP(raw)
	if err != nil {
		t.Fatalf("ParsePTCP: %v", err)
	}
	if got.Rlid != 1 || got.Llid != 2 || got.Pid != 3 || got.Lmid != 4 || got.Rmid != 5 {
		t.Fatalf("header mismatch: %+v", got)
	}
	if string(got.Body) != "\xDE\xAD" {
		t.Fatalf("body mismatch: %x", got.Body)
	}
}

func TestPTCPPayloadRoundtrip(t *testing.T) {
	pl := &PTCPPayload{Realm: 0x781e4db2, Payload: []byte("OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")}
	raw := pl.Bytes()
	got, err := ParsePTCPPayload(raw)
	if err != nil {
		t.Fatalf("ParsePTCPPayload: %v", err)
	}
	if got.Realm != pl.Realm || string(got.Payload) != string(pl.Payload) {
		t.Fatalf("payload mismatch: %+v", got)
	}
}

func TestDevInfoCryptoRoundtrip(t *testing.T) {
	// AES-OFB is symmetric: encrypting with the SDK keys and decrypting via
	// decryptDevInfoInfo must return the original plaintext.
	plain := []byte(`{"randsalt":"abc123","devP2PVersion":"6.6.5"}`)

	block, err := aes.NewCipher([]byte(DEVINFO_KEY))
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	stream := cipher.NewOFB(block, []byte(DEVINFO_IV))
	enc := make([]byte, len(plain))
	stream.XORKeyStream(enc, plain)

	got, err := decryptDevInfoInfo(base64.StdEncoding.EncodeToString(enc))
	if err != nil {
		t.Fatalf("decryptDevInfoInfo: %v", err)
	}
	if string(got) != string(plain) {
		t.Fatalf("roundtrip mismatch: %q", got)
	}
}

func TestParseDHResponse(t *testing.T) {
	raw := "HTTP/1.1 200 Server Nat Info!\r\nCSeq: 42\r\n\r\n<body><PubAddr>91.210.92.130:25024</PubAddr><Policy>p2p,udprelay</Policy></body>"
	res := ParseDHResponse(raw)
	if res.Code != 200 || res.Status != "Server Nat Info!" {
		t.Fatalf("status line mismatch: %d %q", res.Code, res.Status)
	}
	if res.Headers["CSeq"] != "42" {
		t.Fatalf("header mismatch: %v", res.Headers)
	}
	if res.Body["body/PubAddr"] != "91.210.92.130:25024" {
		t.Fatalf("body mismatch: %v", res.Body)
	}
	if res.Body["body/Policy"] != "p2p,udprelay" {
		t.Fatalf("body policy mismatch: %v", res.Body)
	}
}

// TestRequestPTCPWindowConstant: the advertised receive window must stay at
// full 0xFFFF no matter how many frames we send — a shrinking window would
// throttle the device's downstream video on long sessions.
func TestRequestPTCPWindowConstant(t *testing.T) {
	rxConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Skipf("udp listen: %v", err)
	}
	defer rxConn.Close()
	port := rxConn.LocalAddr().(*net.UDPAddr).Port

	u := NewUDP("127.0.0.1", port, false)
	defer u.Close()

	hb := []byte{0x13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	for i := 0; i < 70000; i++ {
		u.RequestPTCP(hb)
	}

	rxConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	n, err := rxConn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	p, err := ParsePTCP(buf[:n])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Pid != 0x0000FFFF {
		t.Fatalf("window not constant: pid=0x%08x", p.Pid)
	}
	if u.ptcpCount != 70000 {
		t.Fatalf("count: %d", u.ptcpCount)
	}
}

// --- fixed realm pool ---

func TestPoolFIFO(t *testing.T) {
	tr := &Tunnel{pools: make(map[int]*poolState), poolTarget: 4}
	tr.pools[80] = &poolState{}
	tr.pushRealm(80, 0x1111)
	tr.pushRealm(80, 0x2222)
	if len(tr.pools[80].queue) != 2 {
		t.Fatalf("queue: %d", len(tr.pools[80].queue))
	}
	r, ok := tr.popRealm(80)
	if !ok || r != 0x1111 {
		t.Fatalf("fifo pop: %x %v", r, ok)
	}
	tr.dropRealm(0x2222)
	if len(tr.pools[80].queue) != 0 {
		t.Fatalf("drop failed: %d", len(tr.pools[80].queue))
	}
}
