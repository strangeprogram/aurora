package main

import (
	"crypto/rand"
	"crypto/sha256"
	"io"
	"net"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

func main() {
	conn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// Generate a new private-public key pair
	var clientPrivate, clientPublic [32]byte
	_, err = rand.Read(clientPrivate[:])
	if err != nil {
		panic(err) // handle error properly in production
	}
	curve25519.ScalarBaseMult(&clientPublic, &clientPrivate)

	// Read server's public key
	var serverPublic [32]byte
	_, err = io.ReadFull(conn, serverPublic[:])
	if err != nil {
		panic(err) // handle error properly in production
	}

	// Send client's public key
	_, err = conn.Write(clientPublic[:])
	if err != nil {
		panic(err) // handle error properly in production
	}

	// Compute shared secret
	var sharedSecret [32]byte
	curve25519.ScalarMult(&sharedSecret, &clientPrivate, &serverPublic)

	// Derive AES key from shared secret using HKDF
	hash := sha256.New
	hkdf := hkdf.New(hash, sharedSecret[:], nil, nil)
	aesKey := make([]byte, 16) // 128-bit key for AES-128
	_, err = io.ReadFull(hkdf, aesKey)
	if err != nil {
		panic(err) // handle error properly in production
	}

	// Continue with secure communication using AES key (omitted for brevity)
	// Send the message "It works"
	message := "It works\n"
	_, err = conn.Write([]byte(message))
	if err != nil {
		panic(err) // handle error properly in production
	}
}
