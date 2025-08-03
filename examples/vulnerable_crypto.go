// Example Go file with quantum-vulnerable cryptography for testing
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"log"
)

// generateRSAKey generates RSA private key - QUANTUM VULNERABLE
func generateRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048) // Will be flagged as vulnerable
}

// generateWeakRSAKey generates weak RSA key - CRITICAL
func generateWeakRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 1024) // CRITICAL - too small
}

// generateECDSAKey generates ECDSA private key - QUANTUM VULNERABLE
func generateECDSAKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// generateECDSAKeyP384 generates ECDSA P-384 key - QUANTUM VULNERABLE
func generateECDSAKeyP384() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
}

func main() {
	// Demo usage - all quantum vulnerable!
	rsaKey, err := generateRSAKey()
	if err != nil {
		log.Fatal(err)
	}
	
	weakRSAKey, err := generateWeakRSAKey()
	if err != nil {
		log.Fatal(err)
	}
	
	ecdsaKey, err := generateECDSAKey()
	if err != nil {
		log.Fatal(err)
	}
	
	ecdsaP384Key, err := generateECDSAKeyP384()
	if err != nil {
		log.Fatal(err)
	}
	
	fmt.Printf("Generated RSA key: %v\n", rsaKey != nil)
	fmt.Printf("Generated weak RSA key: %v\n", weakRSAKey != nil)
	fmt.Printf("Generated ECDSA key: %v\n", ecdsaKey != nil)
	fmt.Printf("Generated ECDSA P-384 key: %v\n", ecdsaP384Key != nil)
	
	fmt.Println("All generated keys are quantum vulnerable!")
	fmt.Println("These will be broken by quantum computers!")
}