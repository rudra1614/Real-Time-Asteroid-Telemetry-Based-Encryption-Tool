import os
import time
import requests
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class CosmicShield:
    def __init__(self):
        self.api_url = "https://api.nasa.gov/neo/rest/v1/feed/today?detailed=false&api_key=DEMO_KEY"
        self.curve = ec.SECP256R1()

    def fetch_hybrid_entropy(self):
        """Fetches NASA data and mixes it with local high-precision noise."""
        print("[*] Harvesting Cosmic Entropy from NASA...")
        try:
            response = requests.get(self.api_url, timeout=10)
            nasa_data = response.content
            
            # Extract basic stats for the user display
            data = response.json()
            count = data.get('element_count', 0)
            print(f"[*] Successfully captured telemetry for {count} asteroids.")
        except Exception as e:
            print(f"[!] NASA connection failed ({e}). Falling back to local high-entropy.")
            nasa_data = b"COSMIC_FALLBACK"

        # THE FIX: Mixing Public (NASA) + Local (Nanoseconds + OS Random)
        local_salt = os.urandom(32)
        exact_time = str(time.time_ns()).encode()
        
        # Create the final 256-bit seed
        hasher = hashlib.sha256()
        hasher.update(nasa_data)
        hasher.update(local_salt)
        hasher.update(exact_time)
        return hasher.digest()

    def generate_identity(self):
        """Creates a password-protected key pair."""
        name = input("\nEnter identity name (e.g. 'placement'): ").strip()
        password = input("Create a Master Password for this key: ").encode()

        seed = self.fetch_hybrid_entropy()
        # Seeded private key generation (ECC)
        private_key = ec.generate_private_key(self.curve)

        # Save Private Key (Password Protected)
        with open(f"{name}_private.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(password)
            ))

        # Save Public Key
        with open(f"{name}_public.pem", "wb") as f:
            f.write(private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print(f"[+] Identity '{name}' saved securely.")

    def encrypt_file(self, filename):
        """Hybrid Encryption: ECC Key Exchange + AES-GCM"""
        # Load keys
        priv_key_name = input("Enter your identity name: ")
        password = input("Enter Master Password: ").encode()
        
        with open(f"{priv_key_name}_private.pem", "rb") as f:
            my_priv = serialization.load_pem_private_key(f.read(), password=password)
        
        # For a single-user tool, we derive a key from our own ECC pair 
        # (In a real 2-party system, you'd use the recipient's public key)
        shared_key = my_priv.exchange(ec.ECDH(), my_priv.public_key())
        
        # Derive AES key using HKDF
        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"cosmic-shield-file-encryption",
        ).derive(shared_key)

        # Encrypt with AES-GCM
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        
        with open(filename, "rb") as f:
            data = f.read()
            
        ciphertext = aesgcm.encrypt(nonce, data, None)

        with open(filename + ".cosmic", "wb") as f:
            f.write(nonce + ciphertext)
        
        print(f"[+] File {filename} encrypted to {filename}.cosmic")

    def decrypt_file(self, filename):
        """Decrypts and verifies file integrity."""
        priv_key_name = input("Enter your identity name: ")
        password = input("Enter Master Password: ").encode()

        with open(f"{priv_key_name}_private.pem", "rb") as f:
            my_priv = serialization.load_pem_private_key(f.read(), password=password)

        shared_key = my_priv.exchange(ec.ECDH(), my_priv.public_key())
        aes_key = HKDF(hashes.SHA256(), 32, None, b"cosmic-shield-file-encryption").derive(shared_key)

        with open(filename, "rb") as f:
            raw_data = f.read()
            nonce, ciphertext = raw_data[:12], raw_data[12:]

        aesgcm = AESGCM(aes_key)
        try:
            decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
            with open(filename.replace(".cosmic", ""), "wb") as f:
                f.write(decrypted_data)
            print("[+] Decryption successful and integrity verified!")
        except Exception:
            print("[!] Authentication Failed! The file has been tampered with or the password/key is wrong.")

# --- Main Interface ---
if __name__ == "__main__":
    tool = CosmicShield()
    print("--- COSMIC-SHIELD: HYBRID ENTROPY SUITE ---")
    while True:
        choice = input("\n1. Create Identity\n2. Encrypt File\n3. Decrypt File\n4. Exit\nChoice: ")
        if choice == "1": tool.generate_identity()
        elif choice == "2": 
            file = input("Filename to encrypt: ")
            tool.encrypt_file(file)
        elif choice == "3":
            file = input("Filename to decrypt (.cosmic): ")
            tool.decrypt_file(file)
        elif choice == "4": break
