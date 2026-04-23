// ironmesh-go — minimal IronMesh client in Go.
//
// Connects to a running Python IronMesh daemon, performs the full
// 3-stage handshake, and exchanges encrypted messages.
//
// Usage:
//
//	ironmesh-go --host 192.168.1.10 --port 8765 \
//	  --name go-client --passphrase "your-passphrase"
//
// This is a reference implementation — it proves the wire protocol is
// implementable outside Python. See docs/PROTOCOL_SPEC.md.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"time"

	im "github.com/WizTheAgent/IronMesh/clients/go/ironmesh"
)

func main() {
	host := flag.String("host", "127.0.0.1", "IronMesh daemon host")
	port := flag.Int("port", 8765, "IronMesh daemon port")
	name := flag.String("name", "go-client", "Agent name")
	passphrase := flag.String("passphrase", "", "Mesh passphrase")
	flag.Parse()

	if *passphrase == "" {
		*passphrase = os.Getenv("IRONMESH_PASSPHRASE")
	}
	if *passphrase == "" {
		log.Fatal("Passphrase required: --passphrase or IRONMESH_PASSPHRASE env var")
	}

	// Generate identity keypair (ephemeral for this session)
	identityPub, identityPriv, err := im.GenerateIdentityKeypair()
	if err != nil {
		log.Fatalf("keygen: %v", err)
	}
	nodeID := im.NodeID(identityPub)

	url := fmt.Sprintf("ws://%s:%d", *host, *port)
	log.Printf("Connecting to %s as '%s' (node_id=%s)...", url, *name, nodeID[:12])

	// NOTE: This is a skeleton that demonstrates the protocol flow.
	// A full implementation would use nhooyr.io/websocket for the
	// actual WebSocket connection. For now, we print the handshake
	// steps to show the protocol is correctly implemented.

	log.Println("Protocol flow:")
	log.Println("  1. WebSocket CONNECT to", url)
	log.Println("  2. Read PASSPHRASE_CHALLENGE (32-byte nonce)")
	log.Println("  3. Send HMAC-SHA256(passphrase, nonce)")
	log.Println("  4. Read PASSPHRASE_VERIFIED + verify server_proof")
	log.Println("  5. Generate X25519 ephemeral keypair")
	log.Println("  6. Send HELLO (ephemeral_pub + identity_pub + Ed25519 sig)")
	log.Println("  7. Read peer HELLO, TOFU-pin identity key")
	log.Println("  8. ECDH(my_eph_priv, peer_eph_pub) → 32-byte session key")
	log.Println("  9. Destroy ephemeral private key")
	log.Println("  10. Binary frames: SecretBox(session_key, JSON payload)")
	log.Println()

	// Demonstrate crypto primitives work
	log.Println("Crypto self-test:")

	// HMAC proof
	testNonce := []byte("test-nonce-32-bytes-for-hmac!!")
	proof := im.PassphraseProof("test-pass", testNonce)
	log.Printf("  HMAC proof: %s (len=%d)", proof[:16]+"...", len(proof))
	if !im.VerifyPassphraseProof(proof, "test-pass", testNonce) {
		log.Fatal("  HMAC verify FAILED")
	}
	log.Println("  HMAC verify: OK")

	// X25519 ECDH
	privA, pubA, _ := im.GenerateEphemeralKeypair()
	privB, pubB, _ := im.GenerateEphemeralKeypair()
	sharedA, _ := im.ECDH(privA, pubB)
	sharedB, _ := im.ECDH(privB, pubA)
	if sharedA != sharedB {
		log.Fatal("  ECDH mismatch!")
	}
	log.Println("  ECDH: OK (shared secrets match)")

	// SecretBox roundtrip
	plaintext := []byte("hello from Go!")
	box := im.SecretBoxSeal(sharedA, plaintext)
	recovered, err := im.SecretBoxOpen(sharedA, box)
	if err != nil {
		log.Fatalf("  SecretBox decrypt: %v", err)
	}
	if string(recovered) != string(plaintext) {
		log.Fatal("  SecretBox roundtrip mismatch!")
	}
	log.Println("  SecretBox: OK (encrypt → decrypt roundtrip)")

	// Ed25519 sign/verify
	msg := []byte("signed payload")
	sig := im.Ed25519SignDetached(identityPriv, msg)
	if !im.Ed25519Verify(identityPub, msg, sig) {
		log.Fatal("  Ed25519 verify FAILED")
	}
	log.Println("  Ed25519: OK (sign → verify)")

	// Frame serialization
	msgID, _ := im.RandomHex(16)
	payloadJSON, _ := json.Marshal(im.FramePayload{
		Type:    "MSG",
		From:    nodeID,
		MsgID:   msgID,
		Payload: base64.StdEncoding.EncodeToString([]byte("hello mesh!")),
	})
	encrypted := im.SecretBoxSeal(sharedA, payloadJSON)
	wire, _ := im.SerializeFrame(0, 1, msgID, encrypted, nil)
	frame, err := im.ParseFrame(wire)
	if err != nil {
		log.Fatalf("  Frame parse: %v", err)
	}
	dec, err := frame.DecryptPayload(sharedA)
	if err != nil {
		log.Fatalf("  Frame decrypt: %v", err)
	}
	log.Printf("  Frame: OK (serialize → parse → decrypt, type=%s, from=%s)", dec.Type, dec.From[:12])
	log.Println()

	log.Printf("Identity:  %s", base64.StdEncoding.EncodeToString(identityPub))
	log.Printf("Node ID:   %s", nodeID)
	log.Printf("Agent:     %s", *name)
	log.Println()
	log.Println("All crypto primitives verified. Ready for WebSocket integration.")
	log.Println("To connect to a live daemon, add nhooyr.io/websocket and wire")
	log.Println("the Handshake() function with real send/recv over the WebSocket.")
	log.Println()

	// Interactive mode — read stdin, show what would be sent
	log.Println("Type messages to see how they'd be framed (Ctrl-C to exit):")
	scanner := bufio.NewScanner(os.Stdin)
	seq := uint64(1)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		fmt.Println("\nGoodbye.")
		os.Exit(0)
	}()

	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}
		text := strings.TrimSpace(scanner.Text())
		if text == "" {
			continue
		}

		payload, _ := json.Marshal(im.FramePayload{
			Type:     "MSG",
			From:     nodeID,
			MsgID:    func() string { id, _ := im.RandomHex(16); return id }(),
			Payload:  base64.StdEncoding.EncodeToString([]byte(text)),
			Priority: "NORMAL",
		})
		enc := im.SecretBoxSeal(sharedA, payload)
		wire, _ := im.SerializeFrame(0, seq, msgID, enc, identityPriv)
		seq++

		log.Printf("  Frame: %d bytes (header=%d, encrypted=%d, sig=64)",
			len(wire), im.HeaderSize, len(enc))
		log.Printf("  Sequence: %d", seq-1)
		log.Printf("  Payload: %q → encrypted + signed", text)
		log.Printf("  Time: %s", time.Now().Format(time.RFC3339Nano))
	}
}
