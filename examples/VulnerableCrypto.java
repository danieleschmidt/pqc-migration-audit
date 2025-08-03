/**
 * Example Java file with quantum-vulnerable cryptography for testing.
 */
package com.example.crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.KeyGenerator;

public class VulnerableCrypto {
    
    /**
     * Generate RSA key pair - QUANTUM VULNERABLE
     */
    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);  // Will be flagged as vulnerable
        return keyGen.generateKeyPair();
    }
    
    /**
     * Generate weak RSA key pair - CRITICAL
     */
    public static KeyPair generateWeakRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);  // CRITICAL - too small
        return keyGen.generateKeyPair();
    }
    
    /**
     * Generate ECC key pair - QUANTUM VULNERABLE
     */
    public static KeyPair generateECCKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        keyGen.initialize(ecSpec);
        return keyGen.generateKeyPair();
    }
    
    /**
     * Generate DSA key pair - QUANTUM VULNERABLE
     */
    public static KeyPair generateDSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }
    
    /**
     * Main method demonstrating vulnerable crypto usage
     */
    public static void main(String[] args) {
        try {
            // All of these are quantum vulnerable!
            KeyPair rsaKey = generateRSAKeyPair();
            KeyPair weakRsaKey = generateWeakRSAKeyPair();
            KeyPair eccKey = generateECCKeyPair();
            KeyPair dsaKey = generateDSAKeyPair();
            
            System.out.println("Generated quantum-vulnerable keys!");
            System.out.println("These will be broken by quantum computers!");
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}