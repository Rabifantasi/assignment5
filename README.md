# 🔒 Secure Data Vault

Secure data storage/retrieval system with AES-256 encryption and Streamlit UI.

## Features
- AES-256 encryption (Fernet)
- PBKDF2 password hashing
- 3-attempt security lock
- In-memory data storage
- Tailwind CSS interface

## 🚀 Quick Start

pip install streamlit cryptography
streamlit run secure_vault.py
Usage
Store Data: Enter text + passkey → Get encrypted token

Retrieve Data: Paste token + passkey → View decrypted data

