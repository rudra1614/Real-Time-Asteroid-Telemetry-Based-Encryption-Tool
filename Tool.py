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
        # Prevent accidental overwrites by naming the identity
        identity = input("Enter a name for this new identity (e.g. 'work', 'key1'): ").strip()
        if not identity: identity = "cosmic"
        
        priv_name = f"{identity}_private.pem"
        pub_name = f"{identity}_public.pem"

        if os.path.exists(priv_name):
            confirm = input(f"[!] {priv_name} already exists. Overwrite? (y/n): ")
            if confirm.lower() != 'y': return

        seed = self.fetch_universe_entropy()
        private_key = ec.generate_private_key(self.curve)
        public_key = private_key.public_key()

        with open(priv_name, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        with open(pub_name, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.SubjectPublicKeyInfo
            ))
        print(f"[+] Success! Keys saved as '{priv_name}' and '{pub_name}'")

    def load_key(self, key_type="private"):
        identity = input(f"Enter the identity name to use (e.g. 'work'): ").strip()
        if not identity: identity = "cosmic"
        filename = f"{identity}_{key_type}.pem"
        
        if not os.path.exists(filename):
            raise FileNotFoundError(f"Key file {filename} not found!")
            
        with open(filename, "rb") as f:
            if key_type == "private":
                return serialization.load_pem_private_key(f.read(), password=None)
            else:
                return serialization.load_pem_public_key(f.read())

    def encrypt_file(self, file_path):
        file_path = os.path.abspath(file_path)
        if not os.path.exists(file_path):
            print(f"[!] File not found: {file_path}")
            return
        
        try:
            pub_key = self.load_key("public")
            with open(file_path, 'rb') as f:
                plaintext = f.read()

            ephemeral_priv = ec.generate_private_key(self.curve)
            shared_secret = ephemeral_priv.exchange(ec.ECDH(), pub_key)
            
            aes_key = HKDF(hashes.SHA256(), 32, None, b'cosmic-file-encryption').derive(shared_secret)
            cipher = AES.new(aes_key, AES.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(plaintext)

            output_path = file_path + ".cosmic"
            with open(output_path, 'wb') as f:
                f.write(ephemeral_priv.public_key().public_bytes(
                    serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))
                f.write(cipher.nonce)
                f.write(tag)
                f.write(ciphertext)
            print(f"[+] File locked: {output_path}")
        except Exception as e:
            print(f"[!] Encryption failed: {e}")

    def decrypt_file(self, encrypted_path):
        encrypted_path = os.path.abspath(encrypted_path)
        if not os.path.exists(encrypted_path):
            print(f"[!] Encrypted file not found: {encrypted_path}")
            return
        
        try:
            priv_key = self.load_key("private")
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

            directory = os.path.dirname(encrypted_path)
            filename = os.path.basename(encrypted_path).replace(".cosmic", "")
            output_path = os.path.join(directory, "DECRYPTED_" + filename)

            with open(output_path, 'wb') as f:
                f.write(plaintext)
            print(f"[+] File unlocked: {output_path}")
        except Exception as e:
            print(f"[!] Decryption failed: {e}")

def main():
    tool = CosmicEncryptor()
    while True:
        print("\n" + "="*35)
        print("     COSMIC SHIELD v2.0")
        print("="*35)
        print("1. Generate New Identity (Keys)")
        print("2. Encrypt a File")
        print("3. Decrypt a File")
        print("4. Exit")
        choice = input("\nAction: ")

        if choice == '1':
            tool.generate_and_save_keys()
        elif choice == '2':
            path = input("File to encrypt: ").strip()
            tool.encrypt_file(path)
        elif choice == '3':
            path = input(".cosmic file to decrypt: ").strip()
            tool.decrypt_file(path)
        elif choice == '4':
            sys.exit()
        else:
            print("[!] Select 1-4.")

if __name__ == "__main__":
    main()
