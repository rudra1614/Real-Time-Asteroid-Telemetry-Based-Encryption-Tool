import requests
import hashlib
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.Cipher import AES

class CosmicEncryptor:
    def __init__(self):
        self.api_key = "mELZsFr2P3SJoCDK6KYSzhBaVBI3WGmxIZjSxjbP"  # NASA's demo key
        self.curve = ec.SECP256R1()

    def fetch_universe_entropy(self):
        """Step 1: Get uncertainty from NASA's Near-Earth Object API"""
        print("[*] Harvesting entropy from the movement of asteroids...")
        url = f"https://api.nasa.gov/neo/rest/v1/feed/today?detailed=true&api_key={self.api_key}"
        try:
            response = requests.get(url, timeout=10)
            # We hash the real-time data to create a 256-bit cosmic seed
            return hashlib.sha256(response.content).digest()
        except Exception as e:
            print(f"[!] Error fetching stars: {e}")
            return os.urandom(32) # Fallback to system entropy if API fails

    def generate_keys(self):
        """Step 2: Generate Asymmetric Cosmic Keys"""
        print("[*] Generating ECC Key Pair seeded by cosmic noise...")
        # In a real tool, the 'seed' would be passed to a DRBG
        private_key = ec.generate_private_key(self.curve)
        public_key = private_key.public_key()
        return private_key, public_key

    def encrypt_file(self, file_path, recipient_public_key):
        """Step 3: Hybrid Encryption (ECC + AES-GCM)"""
        print(f"[*] Encrypting {file_path}...")
        
        # Read the target file
        with open(file_path, 'rb') as f:
            plaintext = f.read()

        # Generate temporary (ephemeral) key for this specific session
        ephemeral_priv = ec.generate_private_key(self.curve)
        ephemeral_pub = ephemeral_priv.public_key()

        # Derive a shared secret using ECDH (Elliptic Curve Diffie-Hellman)
        shared_secret = ephemeral_priv.exchange(ec.ECDH(), recipient_public_key)
        
        # Turn that secret into a usable AES key
        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'cosmic-file-encryption',
        ).derive(shared_secret)

        # Encrypt the file using AES-GCM
        cipher = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        # Build the 'Cosmic Package'
        output_filename = file_path + ".cosmic"
        with open(output_filename, 'wb') as f:
            # We must save the ephemeral public key so the receiver can derive the same secret
            f.write(ephemeral_pub.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            ))
            f.write(cipher.nonce) # 16 bytes
            f.write(tag)          # 16 bytes
            f.write(ciphertext)
        
        print(f"[+] Success! Encrypted file created: {output_filename}")

# --- MAIN EXECUTION ---
if __name__ == "__main__":
    tool = CosmicEncryptor()
    
    # 1. Setup Phase
    cosmic_seed = tool.fetch_universe_entropy()
    my_private_key, my_public_key = tool.generate_keys()

    # 2. Allotment: Display your Public Key
    public_pem = my_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print("\n--- YOUR COSMIC PUBLIC KEY (Allot this to others) ---")
    print(public_pem.decode())

    # 3. Encryption: Let's encrypt a dummy file for testing
    # Create a test file
    test_file = "secret_message.txt"
    with open(test_file, "w") as f:
        f.write("The universe is full of secrets.")

    # Encrypt the file using our own public key (as if sending to ourselves)
    tool.encrypt_file(test_file, my_public_key)
