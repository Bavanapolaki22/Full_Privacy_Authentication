🛡️ Zero-Trust Privacy-Safe HE Vault

This project provides a robust, zero-trust authentication and multi-format data storage solution using Homomorphic Encryption (HE).

🚀 NEW PERSISTENCE FEATURE:
- Data Persistence: The vault now saves your encrypted data to a file (`vault_data.pkl`). This means your registration, secret messages, and uploaded files will survive server restarts.

🚀 SECURITY FEATURES:
- Zero-Trust Keys: Keys are derived from your password on-the-fly. The server never stores them.
- Two-Factor Authorization: Password required for both encryption and decryption.
- Mathematical Blinding: Data is transformed into massive integers: E(m) = m + (Noise * Key * Prime).
- PBKDF2-HMAC-SHA256: Industry-standard salted hashing for secure login.

🛠️ TECHNOLOGIES:
- Backend: Flask (Python)
- Storage: Persistent Pickle Vault
- Encryption: Zero-Trust Homomorphic Simulation
- UI: Bootstrap 5, AJAX

🚀 RUNNING THE APP:
1. Install dependencies: `pip install flask`
2. Run: `python app.py`
3. Visit: `http://127.0.0.1:5000`

📖 HOW IT WORKS:
1. Registration: Generates a unique salt for your password.
2. Encryption: Uses your password to derive a 128-bit key. Every byte is blinded.
3. Decryption: When authorized, the system derives the key again and removes the blinding.
4. Persistence: All encrypted data is safely saved to disk.
