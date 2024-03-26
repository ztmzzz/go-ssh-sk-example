package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
	"strings"
)

type SkEd25519PublicKey struct {
	// application is a URL-like string, typically "ssh:" for SSH.
	// see openssh/PROTOCOL.u2f for details.
	application string
	ed25519.PublicKey
}
type SKEd25519PrivateKey struct {
	SkEd25519PublicKey
	Application string
	Flags       uint8
	Keyhandle   []byte
	Reserved    string
}
type openSSHSKEd25519PrivateKey struct {
	Pub         []byte
	Application string
	Flags       uint8
	Keyhandle   []byte
	Reserved    string
	Comment     string
	Pad         []byte `ssh:"rest"`
}

func parseOpenSSHPrivateKey(key []byte, decrypt openSSHDecryptFunc) (crypto.PrivateKey, error) {
	if len(key) < len(privateKeyAuthMagic) || string(key[:len(privateKeyAuthMagic)]) != privateKeyAuthMagic {
		return nil, errors.New("ssh: invalid openssh private key format")
	}
	remaining := key[len(privateKeyAuthMagic):]

	var w openSSHEncryptedPrivateKey
	if err := ssh.Unmarshal(remaining, &w); err != nil {
		return nil, err
	}
	if w.NumKeys != 1 {
		// We only support single key files, and so does OpenSSH.
		// https://github.com/openssh/openssh-portable/blob/4103a3ec7/sshkey.c#L4171
		return nil, errors.New("ssh: multi-key files are not supported")
	}

	privKeyBlock, err := decrypt(w.CipherName, w.KdfName, w.KdfOpts, w.PrivKeyBlock)
	if err != nil {
		if err, ok := err.(*ssh.PassphraseMissingError); ok {
			pub, errPub := ssh.ParsePublicKey(w.PubKey)
			if errPub != nil {
				return nil, fmt.Errorf("ssh: failed to parse embedded public key: %v", errPub)
			}
			err.PublicKey = pub
		}
		return nil, err
	}

	var pk1 openSSHPrivateKey
	if err := ssh.Unmarshal(privKeyBlock, &pk1); err != nil || pk1.Check1 != pk1.Check2 {
		if w.CipherName != "none" {
			return nil, x509.IncorrectPasswordError
		}
		return nil, errors.New("ssh: malformed OpenSSH key")
	}

	switch pk1.Keytype {
	//The only difference between this function and the library
	case ssh.KeyAlgoSKED25519:
		var key openSSHSKEd25519PrivateKey
		if err := ssh.Unmarshal(pk1.Rest, &key); err != nil {
			return nil, err
		}
		if err := checkOpenSSHKeyPadding(key.Pad); err != nil {
			return nil, err
		}
		return SKEd25519PrivateKey{
			SkEd25519PublicKey: SkEd25519PublicKey{
				application: key.Application,
				PublicKey:   ed25519.PublicKey(key.Pub),
			},
			Application: key.Application,
			Flags:       key.Flags,
			Keyhandle:   key.Keyhandle,
			Reserved:    key.Reserved,
		}, nil
	default:
		return nil, errors.New("ssh: unhandled key type")
	}
}

// The following code is the same as the ssh library
const privateKeyAuthMagic = "openssh-key-v1\x00"

type openSSHDecryptFunc func(CipherName, KdfName, KdfOpts string, PrivKeyBlock []byte) ([]byte, error)
type openSSHEncryptedPrivateKey struct {
	CipherName   string
	KdfName      string
	KdfOpts      string
	NumKeys      uint32
	PubKey       []byte
	PrivKeyBlock []byte
}
type openSSHPrivateKey struct {
	Check1  uint32
	Check2  uint32
	Keytype string
	Rest    []byte `ssh:"rest"`
}
type skFields struct {
	// Flags contains U2F/FIDO2 flags such as 'user present'
	Flags byte
	// Counter is a monotonic signature counter which can be
	// used to detect concurrent use of a private key, should
	// it be extracted from hardware.
	Counter uint32
}

var hashFuncs = map[string]crypto.Hash{
	ssh.KeyAlgoRSA:       crypto.SHA1,
	ssh.KeyAlgoRSASHA256: crypto.SHA256,
	ssh.KeyAlgoRSASHA512: crypto.SHA512,
	ssh.KeyAlgoDSA:       crypto.SHA1,
	ssh.KeyAlgoECDSA256:  crypto.SHA256,
	ssh.KeyAlgoECDSA384:  crypto.SHA384,
	ssh.KeyAlgoECDSA521:  crypto.SHA512,
	// KeyAlgoED25519 doesn't pre-hash.
	ssh.KeyAlgoSKECDSA256: crypto.SHA256,
	ssh.KeyAlgoSKED25519:  crypto.SHA256,
}

func encryptedBlock(block *pem.Block) bool {
	return strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED")
}
func unencryptedOpenSSHKey(cipherName, kdfName, kdfOpts string, privKeyBlock []byte) ([]byte, error) {
	if kdfName != "none" || cipherName != "none" {
		return nil, &ssh.PassphraseMissingError{}
	}
	if kdfOpts != "" {
		return nil, errors.New("ssh: invalid openssh private key")
	}
	return privKeyBlock, nil
}
func checkOpenSSHKeyPadding(pad []byte) error {
	for i, b := range pad {
		if int(b) != i+1 {
			return errors.New("ssh: padding not as expected")
		}
	}
	return nil
}
func ParseRawPrivateKey(pemBytes []byte) (interface{}, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}

	if encryptedBlock(block) {
		return nil, &ssh.PassphraseMissingError{}
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	// RFC5208 - https://tools.ietf.org/html/rfc5208
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "OPENSSH PRIVATE KEY":
		return parseOpenSSHPrivateKey(block.Bytes, unencryptedOpenSSHKey)
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}
}
func (k *SkEd25519PublicKey) Type() string {
	return ssh.KeyAlgoSKED25519
}
func (k *SkEd25519PublicKey) Marshal() []byte {
	w := struct {
		Name        string
		KeyBytes    []byte
		Application string
	}{
		ssh.KeyAlgoSKED25519,
		[]byte(k.PublicKey),
		k.application,
	}
	return ssh.Marshal(&w)
}
func (k *SkEd25519PublicKey) Verify(data []byte, sig *ssh.Signature) error {
	if sig.Format != k.Type() {
		return fmt.Errorf("ssh: signature type %s for key type %s", sig.Format, k.Type())
	}
	if l := len(k.PublicKey); l != ed25519.PublicKeySize {
		return fmt.Errorf("invalid size %d for Ed25519 public key", l)
	}

	h := hashFuncs[sig.Format].New()
	h.Write([]byte(k.application))
	appDigest := h.Sum(nil)

	h.Reset()
	h.Write(data)
	dataDigest := h.Sum(nil)

	var edSig struct {
		Signature []byte `ssh:"rest"`
	}

	if err := ssh.Unmarshal(sig.Blob, &edSig); err != nil {
		return err
	}

	var skf skFields
	if err := ssh.Unmarshal(sig.Rest, &skf); err != nil {
		return err
	}

	blob := struct {
		ApplicationDigest []byte `ssh:"rest"`
		Flags             byte
		Counter           uint32
		MessageDigest     []byte `ssh:"rest"`
	}{
		appDigest,
		skf.Flags,
		skf.Counter,
		dataDigest,
	}

	original := ssh.Marshal(blob)

	if ok := ed25519.Verify(k.PublicKey, original, edSig.Signature); !ok {
		return errors.New("ssh: signature did not verify")
	}

	return nil
}
