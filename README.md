🚀 Astral-Encrypt0r: Hybrid Entropy Encryption Suite

Astral-Encrypt0r is a high-integrity cryptographic tool that bridges astronomical physics with modern cybersecurity. It leverages real-time asteroid telemetry from NASA’s NeoWs API as a non-deterministic entropy source to seed industry-standard hybrid encryption (ECC + AES-GCM).

🌟 Key Features

    Celestial Entropy Harvesting: Uses live NASA orbital data (velocity, miss-distance, and orbit determination timestamps) to initialize cryptographic seeds.

    Hybrid Asymmetric Architecture: * Identity: Elliptic Curve Cryptography (SECP256R1) for robust, efficient key management.

    Encryption: AES-256-GCM for high-speed file encryption with built-in integrity verification (Authenticated Encryption).

    Defense-in-Depth Entropy: Implements a Hybrid Seed Model that mixes public NASA telemetry with local high-precision system noise (time_ns) and OS-level entropy (os.urandom).

    Security at Rest: Private keys are stored using PKCS8 serialization and are encrypted with a Master Password using PBKDF2/Scrypt.

    Tamper Detection: Automatically detects and rejects files if even a single bit has been altered during storage or transit.

🛠️ Technical Stack

    Language: Python 3.x

    Libraries: cryptography.io, requests, hashlib

    API: NASA Near-Earth Object Web Service (NeoWs)

    Security Standards: NIST-compliant curves and authenticated encryption modes.

🚀 Getting Started
1. Prerequisites and Installation

Ensure you have Python installed and the necessary cryptographic libraries:
Bash

    1. pip install cryptography requests

    2. git clone https://github.com/your-username/Astral-Encrypt0r.git
    
    3. cd Astral-Encrypt0r

    4. python3 -m venv venv

    5. source venv/bin/activate

    6. pip install -r requirements.txt

2. 🖥 How to Use

Run the interactive suite:
Bash

    python3 Tool.py

Workflow:
    
    Create Identity: Generates your celestial-seeded key pair.
    
    Encrypt File: Locks any file using your ECC identity and NASA entropy.

    Decrypt File: Unlocks your .cosmic files and verifies they haven't been tampered with.


Generate Identity: Create a named key pair (e.g., placement_key).

<img width="712" height="337" alt="image" src="https://github.com/user-attachments/assets/72ac12ca-dd8a-4a20-99fb-11b4155d1f69" />


Encrypt: Provide a file path and the identity name. The tool generates a .cosmic file.

<img width="530" height="318" alt="image" src="https://github.com/user-attachments/assets/b3318fbc-f13b-487f-9ae7-beccd6f8c024" />


<img width="152" height="98" alt="image" src="https://github.com/user-attachments/assets/e1904c32-346b-409c-a9fa-8d2ddd7428fd" />



Decrypt: Provide the .cosmic file path and your identity name to recover the original file.

<img width="868" height="300" alt="image" src="https://github.com/user-attachments/assets/f85c2766-7be0-48e6-a6d2-88a06d422947" />
    
<img width="108" height="118" alt="image" src="https://github.com/user-attachments/assets/3406409f-f10c-4617-86ca-4ca87ae7ea4a" />

🔬 Cryptographic Philosophy

This project adheres to Kerckhoffs's Principle: the security of the system resides entirely in the key, not the secrecy of the algorithm. By utilizing external, physical phenomena (asteroid orbits) for entropy, Astral-Encrypt0r mitigates the risks associated with predictable software-based PRNGs, similar to the philosophy used in Cloudflare’s LavaRand.

