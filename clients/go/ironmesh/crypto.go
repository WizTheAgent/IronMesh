package ironmesh

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/secretbox"
)

// GenerateEphemeralKeypair creates a fresh X25519 keypair for ECDH.
func GenerateEphemeralKeypair() (privateKey [32]byte, publicKey [32]byte, err error) {
	_, err = rand.Read(privateKey[:])
	if err != nil {
		return
	}
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return
}

// ECDH computes the X25519 shared secret.
func ECDH(myPrivate [32]byte, peerPublic [32]byte) ([32]byte, error) {
	var shared [32]byte
	result, err := curve25519.X25519(myPrivate[:], peerPublic[:])
	if err != nil {
		return shared, err
	}
	copy(shared[:], result)
	return shared, nil
}

// GenerateIdentityKeypair creates an Ed25519 identity keypair.
func GenerateIdentityKeypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	return pub, priv, err
}

// NodeID computes the IronMesh node_id: SHA-256(ed25519_public)[:16] as 32 hex chars.
func NodeID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:16])
}

// PassphraseProof computes HMAC-SHA256(passphrase, nonce).
func PassphraseProof(passphrase string, nonce []byte) string {
	mac := hmac.New(sha256.New, []byte(passphrase))
	mac.Write(nonce)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyPassphraseProof checks HMAC-SHA256.
func VerifyPassphraseProof(proof string, passphrase string, nonce []byte) bool {
	expected := PassphraseProof(passphrase, nonce)
	return hmac.Equal([]byte(proof), []byte(expected))
}

// SecretBoxSeal encrypts plaintext with NaCl SecretBox (XSalsa20-Poly1305).
// Returns nonce (24 bytes) + ciphertext.
func SecretBoxSeal(key [32]byte, plaintext []byte) []byte {
	var nonce [24]byte
	rand.Read(nonce[:])
	encrypted := secretbox.Seal(nonce[:], plaintext, &nonce, &key)
	return encrypted
}

// SecretBoxOpen decrypts NaCl SecretBox. Input is nonce (24) + ciphertext.
func SecretBoxOpen(key [32]byte, box []byte) ([]byte, error) {
	if len(box) < 24 {
		return nil, errors.New("ciphertext too short")
	}
	var nonce [24]byte
	copy(nonce[:], box[:24])
	plaintext, ok := secretbox.Open(nil, box[24:], &nonce, &key)
	if !ok {
		return nil, errors.New("decryption failed: authentication tag mismatch")
	}
	return plaintext, nil
}

// Ed25519SignDetached produces a 64-byte detached Ed25519 signature.
func Ed25519SignDetached(privateKey []byte, message []byte) []byte {
	if len(privateKey) == 32 {
		// Seed form — expand to full 64-byte private key
		privateKey = ed25519.NewKeyFromSeed(privateKey)
	}
	sig := ed25519.Sign(privateKey, message)
	return sig
}

// Ed25519Verify checks a detached Ed25519 signature.
func Ed25519Verify(publicKey ed25519.PublicKey, message, sig []byte) bool {
	return ed25519.Verify(publicKey, message, sig)
}

// RandomHex generates n random bytes as a hex string.
func RandomHex(n int) (string, error) {
	buf := make([]byte, n)
	_, err := rand.Read(buf)
	if err != nil {
		return "", fmt.Errorf("random: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
