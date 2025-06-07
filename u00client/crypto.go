package u00client

import (
	"crypto/ed25519"
	"encoding/hex"
)

func GenerateKeyPair() (privKey []byte, pubKey []byte) {
	pubKey, privKey, _ = ed25519.GenerateKey(nil)
	return privKey, pubKey
}

func GenerateSignature(privKey []byte, data []byte) string {
	signature := ed25519.Sign(privKey, data)
	return "0x" + hex.EncodeToString(signature)
}

func VerifySignature(address string, data []byte, signature string) bool {
	if len(signature) != 130 {
		return false
	}
	signatureBytes, err := hex.DecodeString(signature[2:])
	if err != nil {
		return false
	}
	if len(signatureBytes) != ed25519.SignatureSize {
		return false
	}
	if len(address) != 66 {
		return false
	}
	pubKey, err := hex.DecodeString(address[2:])
	if err != nil {
		return false
	}
	return ed25519.Verify(pubKey, data, signatureBytes)
}
