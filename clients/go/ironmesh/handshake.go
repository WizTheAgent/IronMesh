package ironmesh

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// HandshakeResult holds the state after a successful handshake.
type HandshakeResult struct {
	SessionKey [32]byte          // ECDH shared secret (SecretBox key)
	PeerNodeID string            // Peer's node_id (32 hex chars)
	PeerName   string            // Peer's agent name
	MyNodeID   string            // Our node_id
	Version    string            // Negotiated protocol version
}

// Handshake performs the full 3-stage IronMesh handshake over a
// send/recv channel (WebSocket, TCP, etc.).
//
// send: function that sends a JSON string to the peer.
// recv: function that reads the next JSON string from the peer.
func Handshake(
	send func(string) error,
	recv func() (string, error),
	passphrase string,
	agentName string,
	identityPub ed25519.PublicKey,
	identityPriv ed25519.PrivateKey,
) (*HandshakeResult, error) {

	// ---- Stage 1: Passphrase authentication ----

	// Read PASSPHRASE_CHALLENGE
	challengeRaw, err := recv()
	if err != nil {
		return nil, fmt.Errorf("stage 1: read challenge: %w", err)
	}
	var challenge struct {
		Type  string `json:"type"`
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal([]byte(challengeRaw), &challenge); err != nil {
		return nil, fmt.Errorf("stage 1: parse challenge: %w", err)
	}
	if challenge.Type != "PASSPHRASE_CHALLENGE" {
		return nil, fmt.Errorf("stage 1: expected PASSPHRASE_CHALLENGE, got %s", challenge.Type)
	}

	nonce, err := hex.DecodeString(challenge.Nonce)
	if err != nil {
		return nil, fmt.Errorf("stage 1: decode nonce: %w", err)
	}

	proof := PassphraseProof(passphrase, nonce)
	resp, _ := json.Marshal(map[string]string{
		"type":  "PASSPHRASE_RESPONSE",
		"proof": proof,
	})
	if err := send(string(resp)); err != nil {
		return nil, fmt.Errorf("stage 1: send proof: %w", err)
	}

	// Read PASSPHRASE_VERIFIED (mutual auth)
	verifiedRaw, err := recv()
	if err != nil {
		return nil, fmt.Errorf("stage 1: read verified: %w", err)
	}
	var verified struct {
		Type        string `json:"type"`
		ServerProof string `json:"server_proof"`
	}
	if err := json.Unmarshal([]byte(verifiedRaw), &verified); err != nil {
		return nil, fmt.Errorf("stage 1: parse verified: %w", err)
	}
	if verified.Type == "PASSPHRASE_REJECTED" {
		return nil, errors.New("stage 1: passphrase rejected by server")
	}
	if verified.Type != "PASSPHRASE_VERIFIED" {
		return nil, fmt.Errorf("stage 1: expected PASSPHRASE_VERIFIED, got %s", verified.Type)
	}

	// Verify server proof (reversed nonce)
	reversedNonce := make([]byte, len(nonce))
	for i, b := range nonce {
		reversedNonce[len(nonce)-1-i] = b
	}
	if !VerifyPassphraseProof(verified.ServerProof, passphrase, reversedNonce) {
		return nil, errors.New("stage 1: server proof verification failed (mutual auth)")
	}

	// ---- Stage 2: HELLO exchange ----

	ephPriv, ephPub, err := GenerateEphemeralKeypair()
	if err != nil {
		return nil, fmt.Errorf("stage 2: keygen: %w", err)
	}

	myNodeID := NodeID(identityPub)

	helloBody := map[string]interface{}{
		"type":             "HELLO",
		"ephemeral_public": base64.StdEncoding.EncodeToString(ephPub[:]),
		"identity_public":  base64.StdEncoding.EncodeToString(identityPub),
		"name":             agentName,
		"protocol_version": "ironmesh/0.6",
		"channel_binding":  hex.EncodeToString(nonce),
	}

	// Canonical JSON (sorted keys, no whitespace) for signing
	canonical, err := json.Marshal(helloBody)
	if err != nil {
		return nil, fmt.Errorf("stage 2: marshal hello: %w", err)
	}

	sig := ed25519.Sign(identityPriv, canonical)
	helloBody["signature"] = base64.StdEncoding.EncodeToString(sig)

	helloJSON, _ := json.Marshal(helloBody)
	if err := send(string(helloJSON)); err != nil {
		return nil, fmt.Errorf("stage 2: send hello: %w", err)
	}

	// Read peer HELLO
	peerHelloRaw, err := recv()
	if err != nil {
		return nil, fmt.Errorf("stage 2: read peer hello: %w", err)
	}
	var peerHello struct {
		Type            string `json:"type"`
		EphemeralPublic string `json:"ephemeral_public"`
		IdentityPublic  string `json:"identity_public"`
		Name            string `json:"name"`
		ProtocolVersion string `json:"protocol_version"`
	}
	if err := json.Unmarshal([]byte(peerHelloRaw), &peerHello); err != nil {
		return nil, fmt.Errorf("stage 2: parse peer hello: %w", err)
	}

	peerEphPubBytes, err := base64.StdEncoding.DecodeString(peerHello.EphemeralPublic)
	if err != nil {
		return nil, fmt.Errorf("stage 2: decode peer ephemeral: %w", err)
	}
	peerIdPubBytes, err := base64.StdEncoding.DecodeString(peerHello.IdentityPublic)
	if err != nil {
		return nil, fmt.Errorf("stage 2: decode peer identity: %w", err)
	}

	// ---- Stage 3: ECDH ----

	var peerEphPub [32]byte
	copy(peerEphPub[:], peerEphPubBytes)

	sessionKey, err := ECDH(ephPriv, peerEphPub)
	if err != nil {
		return nil, fmt.Errorf("stage 3: ECDH: %w", err)
	}

	// Wipe ephemeral private key
	for i := range ephPriv {
		ephPriv[i] = 0
	}

	peerNodeID := NodeID(ed25519.PublicKey(peerIdPubBytes))

	return &HandshakeResult{
		SessionKey: sessionKey,
		PeerNodeID: peerNodeID,
		PeerName:   peerHello.Name,
		MyNodeID:   myNodeID,
		Version:    peerHello.ProtocolVersion,
	}, nil
}
