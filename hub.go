package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

func main() {
	listener, err := net.Listen("tcp", "localhost:8080")
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	println("Server is listening on localhost:8080")

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue // handle error properly in production
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// Generate a new private-public key pair
	var serverPrivate, serverPublic [32]byte
	_, err := rand.Read(serverPrivate[:])
	if err != nil {
		panic(err) // handle error properly in production
	}
	curve25519.ScalarBaseMult(&serverPublic, &serverPrivate)

	// Send server's public key
	_, err = conn.Write(serverPublic[:])
	if err != nil {
		panic(err) // handle error properly in production
	}

	// Read client's public key
	var clientPublic [32]byte
	_, err = io.ReadFull(conn, clientPublic[:])
	if err != nil {
		panic(err) // handle error properly in production
	}

	// Compute shared secret
	var sharedSecret [32]byte
	curve25519.ScalarMult(&sharedSecret, &serverPrivate, &clientPublic)

	// Derive AES key from shared secret using HKDF
	hash := sha256.New
	hkdf := hkdf.New(hash, sharedSecret[:], nil, nil)
	aesKey := make([]byte, 16) // 128-bit key for AES-128
	_, err = io.ReadFull(hkdf, aesKey)
	if err != nil {
		panic(err) // handle error properly in production
	}

	// Continue with secure communication using AES key (omitted for brevity)
	// Continuously read messages from the bot
	reader := bufio.NewReader(conn)
	for {
		message, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				fmt.Println("Bot closed the connection")
				break
			}
			fmt.Println("Error reading:", err)
			break
		}
		fmt.Printf("Received message from bot: %s", message)
		// Add logic to handle the message, respond, or exit based on certain conditions
	}
}
