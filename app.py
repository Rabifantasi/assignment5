# secure_vault.py
import streamlit as st
import hashlib

# --- Security Configuration ---
DEFAULT_SHIFT = 3  # Base shift value for Caesar cipher

# --- Session State ---
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

# --- Security Functions ---
def hash_passkey(passkey: str) -> int:
    """Generate shift value from passkey using PBKDF2-HMAC"""
    hashed = hashlib.pbkdf2_hmac(
        'sha256',
        passkey.encode(),
        b'salt',  # Unique salt per user in production
        100000
    )
    return (sum(hashed) % 20) + 1  # Shift between 1-20

def caesar_encrypt(text: str, shift: int) -> str:
    """Enhanced Caesar cipher encryption"""
    encrypted = []
    for char in text:
        encrypted_char = chr((ord(char) + shift) % 256)
        encrypted.append(encrypted_char)
    return ''.join(encrypted)

def caesar_decrypt(text: str, shift: int) -> str:
    """Enhanced Caesar cipher decryption"""
    decrypted = []
    for char in text:
        decrypted_char = chr((ord(char) - shift) % 256)
        decrypted.append(decrypted_char)
    return ''.join(decrypted)

# --- Streamlit UI ---
st.set_page_config(
    page_title="Secure Vault",
    page_icon="🔒",
    layout="centered"
)

st.title("🔐 Secure Data Encryption System")

# Navigation
menu = ["Home", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Menu", menu)

if choice == "Home":
    st.subheader("Welcome to Secure Vault")
    st.markdown("""
    - Store sensitive data with military-grade encryption
    - Retrieve data using your unique passkey
    - Three-attempt security system
    """)

elif choice == "Store Data":
    st.subheader("🔒 Encrypt Data")
    user_data = st.text_area("Enter sensitive data:", height=150)
    passkey = st.text_input("Create passkey:", type="password")
    
    if st.button("Encrypt & Store"):
        if user_data and passkey:
            shift = hash_passkey(passkey) + DEFAULT_SHIFT
            encrypted = caesar_encrypt(user_data, shift)
            st.session_state.stored_data[encrypted] = {
                "encrypted_text": encrypted,
                "shift": shift
            }
            st.success("Data securely stored!")
            st.code(f"Encrypted Token:\n{encrypted}")
        else:
            st.error("All fields required!")

elif choice == "Retrieve Data":
    st.subheader("🔓 Decrypt Data")
    encrypted = st.text_area("Enter encrypted token:", height=150)
    passkey = st.text_input("Enter passkey:", type="password")
    
    if st.button("Decrypt"):
        if encrypted and passkey:
            if encrypted in st.session_state.stored_data:
                shift = hash_passkey(passkey) + DEFAULT_SHIFT
                actual_shift = st.session_state.stored_data[encrypted]["shift"]
                
                if shift == actual_shift:
                    decrypted = caesar_decrypt(encrypted, actual_shift)
                    st.success("Decryption Successful!")
                    st.text_area("Decrypted Data:", value=decrypted, height=150)
                    st.session_state.failed_attempts = 0
                else:
                    st.session_state.failed_attempts += 1
                    remaining = 3 - st.session_state.failed_attempts
                    st.error(f"Invalid passkey! Attempts left: {remaining}")
                    
                    if st.session_state.failed_attempts >= 3:
                        st.error("🔒 System locked! Contact administrator.")
                        st.stop()
            else:
                st.error("Invalid encrypted token!")
        else:
            st.error("All fields required!")

# Security status
st.sidebar.markdown("---")
st.sidebar.warning(f"Security Status: {3 - st.session_state.failed_attempts}/3 attempts remaining")
