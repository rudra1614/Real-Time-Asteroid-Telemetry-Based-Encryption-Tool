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
        self.api_key = "DEMO_KEY"
        self.curve = ec.SECP256R1()

    def fetch_universe_entropy(self):
        print("[*] Contacting NASA for real-time asteroid telemetry...")
        url = f"https://api.nasa.gov/neo/rest/v1/feed/today?detailed=true&api_key={self.api_key}"
        try:
            response = requests.get(url, timeout=10)
            return hashlib.sha256(response.content).digest()
        except:
            print("[!] Cosmic connection failed. Using local entropy.")
            return os.urandom(32)

    def generate_and_save_keys(self):
        seed = self.fetch_universe_entropy()
        # Note: In production, the seed would initialize a DRBG
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
        with open("cosmic_private.pem", "rb") as key_file:
            return serialization.load_pem_private_key(key_file.read(), password=None)

    def load_public_key(self):
        with open("cosmic_public.pem", "rb") as key_file:
            return serialization.load_pem_public_key(key_file.read())

    def encrypt_file(self, file_path):
        if not os.path.exists(file_path):
            print("[!] File not found!")
            return
        
        pub_key = self.load_public_key()
        with open(file_path, 'rb') as f:
            plaintext = f.read()

        ephemeral_priv = ec.generate_private_key(self.curve)
        shared_secret = ephemeral_priv.exchange(ec.ECDH(), pub_key)
        
        aes_key = HKDF(hashes.SHA256(), 32, None, b'cosmic-file-encryption').derive(shared_secret)
        cipher = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        with open(file_path + ".cosmic", 'wb') as f:
            f.write(ephemeral_priv.public_key().public_bytes(
                serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))
            f.write(cipher.nonce)
            f.write(tag)
            f.write(ciphertext)
        print(f"[+] File locked: {file_path}.cosmic")

    def decrypt_file(self, encrypted_path):
        if not os.path.exists(encrypted_path):
            print("[!] Encrypted file not found!")
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

        output_path = "DECRYPTED_" + encrypted_path.replace(".cosmic", "")
        with open(output_path, 'wb') as f:
            f.write(plaintext)
        print(f"[+] File unlocked: {output_path}")

def main():
    tool = CosmicEncryptor()
    while True:
        print("\n--- COSMIC ENCRYPTION SUITE ---")
        print("1. Generate New Identity (Keys)")
        print("2. Encrypt a File")
        print("3. Decrypt a File")
        print("4. Exit")
        choice = input("Select an option: ")

        if choice == '1':
            tool.generate_and_save_keys()
        elif choice == '2':
            path = input("Enter file path to encrypt: ")
            tool.encrypt_file(path)
        elif choice == '3':
            path = input("Enter .cosmic file path to decrypt: ")
            tool.decrypt_file(path)
        elif choice == '4':
            sys.exit()
        else:
            print("[!] Invalid choice.")

if __name__ == "__main__":
    main()
