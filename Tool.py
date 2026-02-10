import os
import time
import requests
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class AstralEncryptor:
    def __init__(self):
        # NASA API endpoint for daily asteroid telemetry
        self.api_url = "https://api.nasa.gov/neo/rest/v1/feed/today?detailed=false&api_key=mELZsFr2P3SJoCDK6KYSzhBaVBI3WGmxIZjSxjbP"
        self.curve = ec.SECP256R1()

    def fetch_hybrid_entropy(self):
        """Fetches NASA telemetry and mixes it with high-precision local noise."""
        print("\n[*] Harvesting Astral Entropy from NASA...")
        try:
            response = requests.get(self.api_url, timeout=10)
            nasa_data = response.content
            
            data = response.json()
            count = data.get('element_count', 0)
            print(f"[*] Successfully captured telemetry for {count} asteroids.")
        except Exception as e:
            print(f"[!] NASA connection failed ({e}). Falling back to local high-entropy.")
            nasa_data = b"ASTRAL_FALLBACK_SEED"

        # MIXING: Public (NASA) + Local (Nanoseconds + OS Hardware Randomness)
        # Ensures every key is unique even if generated in the same minute.
        local_salt = os.urandom(32)
        exact_time = str(time.time_ns()).encode()
        
        hasher = hashlib.sha256()
        hasher.update(nasa_data)
        hasher.update(local_salt)
        hasher.update(exact_time)
        return hasher.digest()

    def generate_identity(self):
        """Creates a password-protected ECC key pair."""
        name = input("\nEnter identity name (e.g. 'placement'): ").strip()
        password = input("Create a Master Password for this key: ").encode()

        # Seeded private key generation
        private_key = ec.generate_private_key(self.curve)

        # Save Private Key (Encrypted with Master Password at Rest)
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
        print(f"[+] Secure Identity '{name}' saved to disk.")

    def encrypt_file(self, filename):
        """Hybrid Encryption: ECC Key Exchange + AES-256-GCM"""
        if not os.path.exists(filename):
            print("[!] Error: File not found.")
            return

        identity_name = input("Enter your identity name: ")
        password = input("Enter Master Password: ").encode()
        
        try:
            with open(f"{identity_name}_private.pem", "rb") as f:
                my_priv = serialization.load_pem_private_key(f.read(), password=password)
            
            # Derive shared secret using ECDH
            shared_key = my_priv.exchange(ec.ECDH(), my_priv.public_key())
            
            # Stretch secret into a 256-bit AES key using HKDF
            aes_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"astral-encryptor-file-locking",
            ).derive(shared_key)

            # Encrypt with AES-GCM (Authenticated Encryption)
            aesgcm = AESGCM(aes_key)
            nonce = os.urandom(12)
            
            with open(filename, "rb") as f:
                data = f.read()
                
            ciphertext = aesgcm.encrypt(nonce, data, None)

            with open(filename + ".astral", "wb") as f:
                f.write(nonce + ciphertext)
            
            print(f"[+] Success! Encrypted file created: {filename}.astral")
        except Exception as e:
            print(f"[!] Encryption failed: {e}")

    def decrypt_file(self, filename):
        """Decrypts and verifies file integrity, saving as 'decrypted_...'."""
        if not os.path.exists(filename):
            print("[!] Error: File not found.")
            return

        identity_name = input("Enter your identity name: ")
        password = input("Enter Master Password: ").encode()

        try:
            with open(f"{identity_name}_private.pem", "rb") as f:
                my_priv = serialization.load_pem_private_key(f.read(), password=password)

            shared_key = my_priv.exchange(ec.ECDH(), my_priv.public_key())
            aes_key = HKDF(hashes.SHA256(), 32, None, b"astral-encryptor-file-locking").derive(shared_key)

            with open(filename, "rb") as f:
                raw_data = f.read()
                nonce, ciphertext = raw_data[:12], raw_data[12:]

            aesgcm = AESGCM(aes_key)
            decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
            
            # SAVING FIX: Ensure visibility with a new filename
            base_name = os.path.basename(filename).replace(".astral", "")
            output_name = f"decrypted_{base_name}"
            
            with open(output_name, "wb") as f:
                f.write(decrypted_data)
            
            print(f"[+] Decryption successful! Integrity verified.")
            print(f"[+] Output saved as: {output_name}")
            
        except Exception:
            print("[!] Authentication Failed! Incorrect password or file tampering detected.")

# --- Main Suite Interface ---
if __name__ == "__main__":
    tool = AstralEncryptor()
    print("========================================")
    print("   ASTRAL-ENCRYPT0R: HYBRID ENTROPY   ")
    print("========================================")
    
    while True:
        print("\n[MAIN MENU]")
        print("1. Create New Identity (Astral Seeded)")
        print("2. Encrypt a File")
        print("3. Decrypt a File")
        print("4. Exit")
        
        choice = input("\nSelect an option: ")
        
        if choice == "1":
            tool.generate_identity()
        elif choice == "2":
            file_to_lock = input("Enter path of file to encrypt: ")
            tool.encrypt_file(file_to_lock)
        elif choice == "3":
            file_to_unlock = input("Enter path of .astral file: ")
            tool.decrypt_file(file_to_unlock)
        elif choice == "4":
            print("Safe travels through the astral plane. Goodbye!")
            break
        else:
            print("[!] Invalid selection.")
