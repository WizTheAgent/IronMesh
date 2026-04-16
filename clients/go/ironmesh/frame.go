// Package ironmesh implements the IronMesh wire protocol in Go.
//
// This is a reference client — it can join an existing Python-hosted
// IronMesh mesh, authenticate, and exchange encrypted messages. It is
// NOT a full daemon (no mDNS, no mesh routing, no persistence).
package ironmesh

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Wire format constants (must match protocol.py).
var Magic = []byte{0xe7, 0xf6}

const (
	Version    = 4
	HeaderSize = 32

	FlagHighPriority     = 0x01
	FlagCriticalPriority = 0x02
	FlagEncrypted        = 0x04
	FlagSigned           = 0x08
)

// Frame represents an IronMesh binary wire frame.
type Frame struct {
	Flags     byte
	Sequence  uint64
	Timestamp uint64 // milliseconds since epoch
	MsgIDHash [8]byte
	Encrypted []byte // SecretBox ciphertext
	Signature []byte // 64-byte Ed25519 sig (if FlagSigned)
}

// FramePayload is the JSON structure inside the encrypted payload.
type FramePayload struct {
	Type            string `json:"type"`
	From            string `json:"from"`
	MsgID           string `json:"msg_id"`
	Payload         string `json:"payload"`          // base64
	Destination     string `json:"destination,omitempty"`
	TTL             int    `json:"ttl,omitempty"`
	Hops            int    `json:"hops,omitempty"`
	Priority        string `json:"priority,omitempty"`
	E2EPayload      string `json:"e2e_payload,omitempty"`
	SourceSignature string `json:"source_signature,omitempty"`
}

// SerializeFrame builds a binary wire frame from components.
func SerializeFrame(
	flags byte,
	sequence uint64,
	msgID string,
	encrypted []byte,
	signingKey []byte, // 64-byte Ed25519 private key; nil = no sig
) ([]byte, error) {
	flags |= FlagEncrypted

	now := uint64(time.Now().UnixMilli())
	idHash := sha256.Sum256([]byte(msgID))

	buf := make([]byte, 0, HeaderSize+len(encrypted)+64)

	// Header (32 bytes)
	buf = append(buf, Magic...)
	buf = append(buf, byte(Version))
	buf = append(buf, flags)

	seqBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(seqBuf, sequence)
	buf = append(buf, seqBuf...)

	tsBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBuf, now)
	buf = append(buf, tsBuf...)

	buf = append(buf, idHash[:8]...)

	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(encrypted)))
	buf = append(buf, lenBuf...)

	// Encrypted payload
	buf = append(buf, encrypted...)

	// Signature (optional)
	if signingKey != nil {
		flags |= FlagSigned
		buf[3] = flags // update flags byte in header
		sig := Ed25519SignDetached(signingKey, encrypted)
		buf = append(buf, sig...)
	}

	return buf, nil
}

// ParseFrame deserializes a binary wire frame. Does NOT decrypt.
func ParseFrame(data []byte) (*Frame, error) {
	if len(data) < HeaderSize {
		return nil, fmt.Errorf("frame too short: %d bytes", len(data))
	}
	if data[0] != Magic[0] || data[1] != Magic[1] {
		return nil, errors.New("invalid magic bytes")
	}
	version := data[2]
	if version != 3 && version != 4 {
		return nil, fmt.Errorf("unsupported version: %d", version)
	}

	f := &Frame{
		Flags:    data[3],
		Sequence: binary.BigEndian.Uint64(data[4:12]),
	}
	f.Timestamp = binary.BigEndian.Uint64(data[12:20])
	copy(f.MsgIDHash[:], data[20:28])

	encLen := binary.BigEndian.Uint32(data[28:32])
	if uint32(len(data)) < 32+encLen {
		return nil, fmt.Errorf("truncated: need %d, have %d", 32+encLen, len(data))
	}
	f.Encrypted = data[32 : 32+encLen]

	if f.Flags&FlagSigned != 0 {
		sigStart := 32 + encLen
		if uint32(len(data)) < sigStart+64 {
			return nil, errors.New("signed frame missing signature bytes")
		}
		f.Signature = data[sigStart : sigStart+64]
	}

	return f, nil
}

// DecryptPayload decrypts the frame's encrypted field using SecretBox.
func (f *Frame) DecryptPayload(sessionKey [32]byte) (*FramePayload, error) {
	if f.Flags&FlagEncrypted == 0 {
		return nil, errors.New("frame not encrypted")
	}
	plaintext, err := SecretBoxOpen(sessionKey, f.Encrypted)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}
	var payload FramePayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("payload JSON: %w", err)
	}
	return &payload, nil
}
