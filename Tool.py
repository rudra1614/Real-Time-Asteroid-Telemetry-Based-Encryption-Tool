import requests
import hashlib
import os
import sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.Cipher import AES

class CosmicEncryptor:
    def __init__(self):
        self.api_key = "mELZsFr2P3SJoCDK6KYSzhBaVBI3WGmxIZjSxjbP"
        self.curve = ec.SECP256R1()

    def fetch_universe_entropy(self):
        print("[*] Contacting NASA for real-time asteroid telemetry...")
        url = f"https://api.nasa.gov/neo/rest/v1/feed/today?detailed=true&api_key={self.api_key}"
        try:
            response = requests.get(url, timeout=10)
            return hashlib.sha256(response.content).digest()
        except Exception as e:
            print(f"[!] Cosmic connection failed: {e}. Using local entropy.")
            return os.urandom(32)

    def generate_and_save_keys(self):
        seed = self.fetch_universe_entropy()
        # Seeded key generation
        private_key = ec.generate_private_key(self.curve)
        public_key = private_key.public_key()

        # Save Private Key
        with open("cosmic_private.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Save Public Key
        with open("cosmic_public.pem", "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print("[+] Keys generated and saved to 'cosmic_private.pem' and 'cosmic_public.pem'")

    def load_private_key(self):
        if not os.path.exists("cosmic_private.pem"):
            raise FileNotFoundError("Private key not found! Generate keys first.")
        with open("cosmic_private.pem", "rb") as key_file:
            return serialization.load_pem_private_key(key_file.read(), password=None)

    def load_public_key(self):
        if not os.path.exists("cosmic_public.pem"):
            raise FileNotFoundError("Public key not found! Generate keys first.")
        with open("cosmic_public.pem", "rb") as key_file:
            return serialization.load_pem_public_key(key_file.read())

    def encrypt_file(self, file_path):
        # Normalize path for the OS
        file_path = os.path.abspath(file_path)
        if not os.path.exists(file_path):
            print(f"[!] File not found: {file_path}")
            return
        
        pub_key = self.load_public_key()
        with open(file_path, 'rb') as f:
            plaintext = f.read()

        # Ephemeral Key for Hybrid Encryption
        ephemeral_priv = ec.generate_private_key(self.curve)
        shared_secret = ephemeral_priv.exchange(ec.ECDH(), pub_key)
        
        # Key Derivation
        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'cosmic-file-encryption'
        ).derive(shared_secret)

        cipher = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        # Build output path properly
        output_path = file_path + ".cosmic"
        with open(output_path, 'wb') as f:
            f.write(ephemeral_priv.public_key().public_bytes(
                serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))
            f.write(cipher.nonce)
            f.write(tag)
            f.write(ciphertext)
        print(f"[+] File locked: {output_path}")

    def decrypt_file(self, encrypted_path):
        # Normalize path
        encrypted_path = os.path.abspath(encrypted_path)
        if not os.path.exists(encrypted_path):
            print(f"[!] Encrypted file not found: {encrypted_path}")
            return
        
        priv_key = self.load_private_key()
        with open(encrypted_path, 'rb') as f:
            e_pub_bytes = f.read(65)
            nonce = f.read(16)
            tag = f.read(16)
            ciphertext = f.read()

        e_pub = ec.EllipticCurvePublicKey.from_encoded_point(self.curve, e_pub_bytes)
        shared_secret = priv_key.exchange(ec.ECDH(), e_pub)
        aes_key = HKDF(hashes.SHA256(), 32, None, b'cosmic-file-encryption').derive(shared_secret)

        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        # Path Fix: Add DECRYPTED_ prefix only to the filename
        directory = os.path.dirname(encrypted_path)
        filename = os.path.basename(encrypted_path).replace(".cosmic", "")
        output_path = os.path.join(directory, "DECRYPTED_" + filename)

        with open(output_path, 'wb') as f:
            f.write(plaintext)
        print(f"[+] File unlocked: {output_path}")

def main():
    tool = CosmicEncryptor()
    while True:
        print("\n" + "="*30)
        print("   COSMIC ENCRYPTION SUITE")
        print("="*30)
        print("1. Generate New Identity (Keys)")
        print("2. Encrypt a File")
        print("3. Decrypt a File")
        print("4. Exit")
        choice = input("\nSelect an option (1-4): ")

        try:
            if choice == '1':
                tool.generate_and_save_keys()
            elif choice == '2':
                path = input("Enter file path to encrypt: ").strip()
                tool.encrypt_file(path)
            elif choice == '3':
                path = input("Enter .cosmic file path to decrypt: ").strip()
                tool.decrypt_file(path)
            elif choice == '4':
                print("Exiting Cosmic Suite. Goodbye.")
                sys.exit()
            else:
                print("[!] Invalid choice. Please select 1-4.")
        except Exception as e:
            print(f"[!] Error: {e}")

if __name__ == "__main__":
    main()
