package main

import "C"
import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"github.com/keys-pub/go-libfido2"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"os"
	"strings"
)

type SkEd25519PrivateKey struct {
	Pub         SkEd25519PublicKey
	Application string
	Flags       uint8
	Keyhandle   []byte
	Reserved    string
}

func (pk *SkEd25519PrivateKey) PublicKey() ssh.PublicKey {
	return &pk.Pub
}

func (pk *SkEd25519PrivateKey) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	type extra struct {
		Flags   byte
		Counter uint32
	}
	sigExtra := extra{}
	var sig []byte
	locs, err := libfido2.DeviceLocations()
	if err != nil {
		log.Fatal(err)
	}
	for _, loc := range locs {
		log.Printf("Using device: %+v\n", loc)
		path := loc.Path
		device, err := libfido2.NewDevice(path)
		if err != nil {
			log.Fatal(err)
		}
		// ask for pin
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Please Enter Pin: ")
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("Error reading from stdin:", err)
			return nil, err
		}
		pin := strings.TrimSpace(input)

		rps, err := device.RelyingParties(pin)
		if err != nil {
			log.Println("Wrong pin")
			continue
		}
		// check if this device has a matching key
		for _, rp := range rps {
			if pk.Application == rp.ID {
				creds, err := device.Credentials(rp.ID, pin)
				if err != nil {
					log.Fatal(err)
				}
				for _, cred := range creds {
					if bytes.Equal(cred.ID, pk.Keyhandle) {
						fmt.Println("Start signing, you may need to touch the key")
						sum := sha256.Sum256(data)
						assertion, err := device.Assertion(
							rp.ID,
							sum[:],
							[][]byte{cred.ID},
							pin,
							&libfido2.AssertionOpts{},
						)
						if err != nil {
							log.Fatal(err)
						}
						sig = assertion.Sig[:]
						sigExtra.Counter = assertion.Counter
						sigExtra.Flags = assertion.Flags
					}
				}
			}
		}
	}
	return &ssh.Signature{
		Format: pk.Pub.Type(),
		Blob:   sig,
		Rest:   ssh.Marshal(sigExtra),
	}, nil
}
