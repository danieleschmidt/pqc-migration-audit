"""Example file with quantum-vulnerable cryptography for testing."""

from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# RSA key generation - QUANTUM VULNERABLE
def generate_rsa_key():
    """Generate RSA private key."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,  # Will be flagged as vulnerable
    )
    return private_key

# Weak RSA key - CRITICAL
def generate_weak_rsa():
    """Generate weak RSA key."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,  # CRITICAL - too small
    )
    return private_key

# ECC key generation - QUANTUM VULNERABLE  
def generate_ecc_key():
    """Generate ECC private key."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key

# DSA key generation - QUANTUM VULNERABLE
def generate_dsa_key():
    """Generate DSA private key.""" 
    private_key = dsa.generate_private_key(
        key_size=2048
    )
    return private_key

# RSA encryption example
def rsa_encrypt_data(public_key, data):
    """Encrypt data with RSA public key."""
    encrypted = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

# ECDSA signing example
def sign_with_ecdsa(private_key, data):
    """Sign data with ECDSA private key."""
    signature = private_key.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )
    return signature

if __name__ == "__main__":
    # Demo usage - all quantum vulnerable!
    rsa_key = generate_rsa_key()
    weak_rsa = generate_weak_rsa()
    ecc_key = generate_ecc_key()
    dsa_key = generate_dsa_key()
    
    print("Generated quantum-vulnerable keys!")
    print("These will be broken by quantum computers!")