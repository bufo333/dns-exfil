// keygen.go
//
// Generate an X25519 key pair for DNS exfiltration with perfect forward secrecy,
// save the private and public keys as raw 32-byte files, and append the public
// key filename to a .env configuration file.
//
// Steps:
// 1. Create a new ephemeral X25519 private key.
// 2. Derive the corresponding public key.
// 3. Write the private key to “server.key” in raw (32-byte) format (0600 perms).
// 4. Write the public key to “server_public.key” in raw (32-byte) format (0644 perms).
// 5. Append “SERVER_PUBLIC_KEY=server_public.key” to “.env”.

package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"log"
	"os"
)

const (
	privateKeyFile = "server.key"
	publicKeyFile  = "server_public.key"
	envFile        = ".env"
	envVarEntry    = "SERVER_PUBLIC_KEY=" + publicKeyFile + "\n"
)

func main() {
	// Generate X25519 key pair
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("failed to generate X25519 key: %v", err)
	}
	pub := priv.PublicKey()

	// Write private key (raw 32 bytes)
	if err := os.WriteFile(privateKeyFile, priv.Bytes(), 0o600); err != nil {
		log.Fatalf("failed to write private key to %s: %v", privateKeyFile, err)
	}
	fmt.Printf("Wrote private key to %s\n", privateKeyFile)

	// Write public key (raw 32 bytes)
	if err := os.WriteFile(publicKeyFile, pub.Bytes(), 0o644); err != nil {
		log.Fatalf("failed to write public key to %s: %v", publicKeyFile, err)
	}
	fmt.Printf("Wrote public key to %s\n", publicKeyFile)

	// Append public key path to .env
	f, err := os.OpenFile(envFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		log.Fatalf("failed to open %s: %v", envFile, err)
	}
	// ensure file is closed and check error
	defer func() {
		if cerr := f.Close(); cerr != nil {
			log.Printf("warning: failed to close %s: %v", envFile, cerr)
		}
	}()

	if _, err := f.WriteString(envVarEntry); err != nil {
		log.Fatalf("failed to append to %s: %v", envFile, err)
	}
	fmt.Printf("Appended %q to %s\n", envVarEntry[:len(envVarEntry)-1], envFile)
}
