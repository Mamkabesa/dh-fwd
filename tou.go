package main

// TOU framing over the TCP relay channel, byte-exact from P2PDll.dll
// (CTcpRelayChannel::parseTouPacket 0x180018660, sendSyn 0x1800158B0,
// sendAck 0x180015B10 — see docs/REVERSE.md Part III, sections 14-15).
//
//   byte 0 = (version << 4) | type        version == 0x1
//   byte 1 = flags/reserved               observed 0x00
//   types: 0 DATA (12B header + BE16 len @2), 1 SYN (20B),
//          2 ACK (16B), 3 KEEPALIVE (12B), 4 SERVICE (12B)

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	touTypeData = 0x00
	touTypeSyn  = 0x01
	touTypeAck  = 0x02
	touTypeKA   = 0x03
	touTypeSrv  = 0x04

	touVersionNibble = 0x10

	touHdrSize      = 12
	touSynSize      = 20
	touAckSize      = 16
	touMaxDataLen   = 0xFFFF
	touMaxPacketLen = 0x10000 // [ch+0x338] bound in parseTouPacket
)

var errTouVersion = errors.New("invalid tou message, wrong version")
var errTouType = errors.New("invalid tou message, unknown type")
var errTouTruncated = errors.New("tou buffer truncated")

func touHeader(typ byte) byte {
	return touVersionNibble | (typ & 0x0F)
}

// touBuildSyn — 20 bytes:
//   [0]=0x11 [1]=0 [2:4]=htons(0) [4:8]=session(BE) [8:14]=0
//   [14:16]=hint(BE) [16:20]=x(BE)
func touBuildSyn(session uint32) []byte {
	b := make([]byte, touSynSize)
	b[0] = touHeader(touTypeSyn)
	binary.BigEndian.PutUint32(b[4:8], session)
	return b
}

// touBuildAck — 16 bytes:
//   [0]=0x12 [4:8]=session(BE) [8:12]=0 [12:16]=value(BE)
func touBuildAck(session, value uint32) []byte {
	b := make([]byte, touAckSize)
	b[0] = touHeader(touTypeAck)
	binary.BigEndian.PutUint32(b[4:8], session)
	binary.BigEndian.PutUint32(b[12:16], value)
	return b
}

// touBuildData — 12-byte header + payload:
//   [0]=0x10 [1]=0 [2:4]=len(BE) [4:8]=session(BE) [8:12]=0
func touBuildData(session uint32, payload []byte) ([]byte, error) {
	if len(payload) > touMaxDataLen {
		return nil, fmt.Errorf("tou payload too large: %d", len(payload))
	}
	b := make([]byte, touHdrSize+len(payload))
	b[0] = touHeader(touTypeData)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(payload)))
	binary.BigEndian.PutUint32(b[4:8], session)
	copy(b[touHdrSize:], payload)
	return b, nil
}

// touBuildKeepalive — 12 bytes: [0]=0x13 [4:8]=session(BE)
func touBuildKeepalive(session uint32) []byte {
	b := make([]byte, touHdrSize)
	b[0] = touHeader(touTypeKA)
	binary.BigEndian.PutUint32(b[4:8], session)
	return b
}

// touBuildService — 12 bytes, secondary service type 4 (observed in SDK).
func touBuildService(session uint32) []byte {
	b := make([]byte, touHdrSize)
	b[0] = touHeader(touTypeSrv)
	binary.BigEndian.PutUint32(b[4:8], session)
	return b
}

// touFixedLen returns the total frame size for fixed-size types,
// ok=false for DATA (variable) and unknown types.
func touFixedLen(firstByte byte) (int, bool) {
	if firstByte&0xF0 != touVersionNibble {
		return 0, false
	}
	switch firstByte & 0x0F {
	case touTypeSyn:
		return touSynSize, true
	case touTypeAck:
		return touAckSize, true
	case touTypeKA, touTypeSrv:
		return touHdrSize, true
	}
	return 0, false
}

// parseTouPacket mirrors CTcpRelayChannel::parseTouPacket: given a frame
// (complete or longer), returns type, session, payload and total length.
// payload is non-nil only for DATA.
func parseTouPacket(frame []byte) (typ byte, session uint32, payload []byte, total int, err error) {
	if len(frame) < 1 {
		return 0, 0, nil, 0, errTouTruncated
	}
	if frame[0]&0xF0 != touVersionNibble {
		return 0, 0, nil, 0, errTouVersion
	}
	typ = frame[0] & 0x0F
	switch typ {
	case touTypeData:
		if len(frame) < touHdrSize {
			return typ, 0, nil, 0, errTouTruncated
		}
		n := int(binary.BigEndian.Uint16(frame[2:4]))
		total = touHdrSize + n
		if total > touMaxPacketLen {
			return typ, 0, nil, 0, fmt.Errorf("tou packet too large: %d", total)
		}
		if len(frame) < total {
			return typ, 0, nil, total, errTouTruncated
		}
		session = binary.BigEndian.Uint32(frame[4:8])
		return typ, session, frame[touHdrSize:total], total, nil
	case touTypeSyn:
		if len(frame) < touSynSize {
			return typ, 0, nil, 0, errTouTruncated
		}
		session = binary.BigEndian.Uint32(frame[4:8])
		return typ, session, nil, touSynSize, nil
	case touTypeAck:
		if len(frame) < touAckSize {
			return typ, 0, nil, 0, errTouTruncated
		}
		session = binary.BigEndian.Uint32(frame[4:8])
		return typ, session, frame[12:16], touAckSize, nil
	case touTypeKA, touTypeSrv:
		if len(frame) < touHdrSize {
			return typ, 0, nil, 0, errTouTruncated
		}
		session = binary.BigEndian.Uint32(frame[4:8])
		return typ, session, nil, touHdrSize, nil
	}
	return typ, 0, nil, 0, errTouType
}
