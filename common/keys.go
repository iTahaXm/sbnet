package common

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/curve25519"
)

// LoadOrCreateEd25519 loads an ed25519 keypair from path.
// Generates and saves a new one if the file does not exist or is corrupt.
func LoadOrCreateEd25519(path string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		privBytes, decErr := hex.DecodeString(strings.TrimSpace(string(data)))
		if decErr == nil && len(privBytes) == ed25519.PrivateKeySize {
			priv := ed25519.PrivateKey(privBytes)
			return priv.Public().(ed25519.PublicKey), priv, nil
		}
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	if writeErr := os.WriteFile(path, []byte(hex.EncodeToString(priv)), 0600); writeErr != nil {
		return nil, nil, fmt.Errorf("save ed25519 key to %s: %w", path, writeErr)
	}
	return pub, priv, nil
}

// LoadOrCreateX25519 loads an X25519 keypair from path.
// Generates and saves a new one if the file does not exist or is corrupt.
func LoadOrCreateX25519(path string) (priv, pub [32]byte, err error) {
	data, readErr := os.ReadFile(path)
	if readErr == nil {
		privBytes, decErr := hex.DecodeString(strings.TrimSpace(string(data)))
		if decErr == nil && len(privBytes) == 32 {
			copy(priv[:], privBytes)
			curve25519.ScalarBaseMult(&pub, &priv)
			return priv, pub, nil
		}
	}
	if _, randErr := rand.Read(priv[:]); randErr != nil {
		return priv, pub, randErr
	}
	curve25519.ScalarBaseMult(&pub, &priv)
	if writeErr := os.WriteFile(path, []byte(hex.EncodeToString(priv[:])), 0600); writeErr != nil {
		return priv, pub, fmt.Errorf("save X25519 key to %s: %w", path, writeErr)
	}
	return priv, pub, nil
}
