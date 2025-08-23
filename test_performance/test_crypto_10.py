# Test crypto file 10
import os
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from Crypto.PublicKey import RSA, ECC

def generate_keys_10():
    # RSA key generation (vulnerable)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048  # quantum-vulnerable
    )
    
    # ECC key generation (vulnerable)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    
    # Legacy RSA
    rsa_key = RSA.generate(2048)
    
    return private_key, ec_key, rsa_key

# Function 10 with crypto patterns
class CryptoManager_10:
    def __init__(self):
        self.private_key = rsa.generate_private_key(65537, 2048)
        self.ec_private = ec.generate_private_key(ec.SECP384R1())
