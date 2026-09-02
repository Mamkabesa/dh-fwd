package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestTouSynLayout(t *testing.T) {
	// Byte-exact vs sendSyn disasm: 0x11, zeros, session BE32 @4.
	syn := touBuildSyn(0xDEADBEEF)
	if len(syn) != touSynSize {
		t.Fatalf("syn len %d", len(syn))
	}
	if syn[0] != 0x11 || syn[1] != 0 || syn[2] != 0 || syn[3] != 0 {
		t.Fatalf("syn header: %x", syn[:4])
	}
	if got := binary.BigEndian.Uint32(syn[4:8]); got != 0xDEADBEEF {
		t.Fatalf("session: %x", got)
	}
	for _, b := range syn[8:] {
		if b != 0 {
			t.Fatalf("syn tail not zero: %x", syn)
		}
	}
}

func TestTouAckLayout(t *testing.T) {
	ack := touBuildAck(0x11223344, 0x55)
	if len(ack) != touAckSize {
		t.Fatalf("ack len %d", len(ack))
	}
	if ack[0] != 0x12 {
		t.Fatalf("ack type byte: %x", ack[0])
	}
	if got := binary.BigEndian.Uint32(ack[4:8]); got != 0x11223344 {
		t.Fatalf("session: %x", got)
	}
	if got := binary.BigEndian.Uint32(ack[12:16]); got != 0x55 {
		t.Fatalf("value: %x", got)
	}
	if !bytes.Equal(ack[8:12], []byte{0, 0, 0, 0}) {
		t.Fatalf("ack [8:12] not zero: %x", ack[8:12])
	}
}

func TestTouDataRoundtrip(t *testing.T) {
	payload := []byte("OPTIONS * RTSP/1.0\r\nCSeq: 100\r\n\r\n")
	frame, err := touBuildData(0xCAFE0001, payload)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if frame[0] != 0x10 {
		t.Fatalf("data type byte: %x", frame[0])
	}
	if n := binary.BigEndian.Uint16(frame[2:4]); int(n) != len(payload) {
		t.Fatalf("len field: %d", n)
	}
	typ, session, got, total, err := parseTouPacket(frame)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if typ != touTypeData || session != 0xCAFE0001 {
		t.Fatalf("hdr mismatch: typ=%d sess=%x", typ, session)
	}
	if !bytes.Equal(got, payload) || total != len(frame) {
		t.Fatalf("payload/total mismatch: %d vs %d", total, len(frame))
	}
}

func TestTouKeepaliveAndService(t *testing.T) {
	for _, tc := range []struct {
		frame []byte
		want  byte
	}{{touBuildKeepalive(7), touTypeKA}, {touBuildService(9), touTypeSrv}} {
		typ, session, payload, total, err := parseTouPacket(tc.frame)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if typ != tc.want || payload != nil || total != touHdrSize {
			t.Fatalf("mismatch: typ=%02x sess=%x total=%d", typ, session, total)
		}
	}
}

func TestParseTouErrors(t *testing.T) {
	// wrong version nibble
	if _, _, _, _, err := parseTouPacket([]byte{0x31, 0, 0, 0}); err == nil {
		t.Fatal("expected version error")
	}
	// unknown type
	if _, _, _, _, err := parseTouPacket([]byte{0x17, 0, 0, 0}); err == nil {
		t.Fatal("expected type error")
	}
	// truncated data frame
	frame, _ := touBuildData(1, bytes.Repeat([]byte{0xAB}, 100))
	if _, _, _, _, err := parseTouPacket(frame[:10]); err == nil {
		t.Fatal("expected truncation error")
	}
	// complete short frames parse
	if _, _, _, _, err := parseTouPacket(touBuildSyn(2)); err != nil {
		t.Fatalf("syn should parse: %v", err)
	}
}

func TestBuildDHRequestShape(t *testing.T) {
	req := string(buildDHRequest("DHPOST", "/tcprelay/client-bind", `{"Token":"T1"}`, true, 42))
	if !bytes.HasPrefix([]byte(req), []byte("DHPOST /tcprelay/client-bind HTTP/1.1\r\nCSeq: 42\r\n")) {
		t.Fatalf("request line/cseq wrong: %q", req)
	}
	if !bytes.Contains([]byte(req), []byte("Content-Length: 14")) {
		t.Fatalf("content-length wrong: %q", req)
	}
	if !bytes.Contains([]byte(req), []byte(`{"Token":"T1"}`)) {
		t.Fatalf("body missing: %q", req)
	}
	if !bytes.Contains([]byte(req), []byte("Authorization: WSSE")) {
		t.Fatalf("wsse missing: %q", req)
	}
}
