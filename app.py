
import streamlit as st
import hashlib
import json
from cryptography.fernet import Fernet


st.set_page_config(
    page_title="Secure Vault",
    page_icon="🔒",
    layout="centered"
)


st.markdown("""
<script src="https://cdn.tailwindcss.com"></script>
<style>
  .st-emotion-cache-1y4p8pa { padding: 2rem !important; }
  .stButton>button { 
    @apply w-full bg-purple-600 hover:bg-purple-700 text-white font-medium py-2 px-4 rounded-lg transition-all shadow-sm;
  }
  .stTextInput input, .stTextArea textarea {
    @apply border-gray-200 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-purple-500 !important;
  }
  .stAlert { 
    @apply rounded-xl border-0 !important;
    .st-emotion-cache-1q7gvkk { padding: 1rem !important; }
  }
</style>
""", unsafe_allow_html=True)

def load_key():
    try:
        with open("secret.key", "rb") as f:
            return f.read()
    except FileNotFoundError:
        key = Fernet.generate_key()
        with open("secret.key", "wb") as f:
            f.write(key)
        return key

KEY = load_key()
cipher = Fernet(KEY)

if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

def hash_passkey(passkey: str) -> str:
    return hashlib.pbkdf2_hmac(
        'sha256',
        passkey.encode('utf-8'),
        b'salt_value',
        100000
    ).hex()

def encrypt_data(text: str) -> str:
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text: str) -> str:
    return cipher.decrypt(encrypted_text.encode()).decode()

def main_container():
    st.markdown("""
    <div class="min-h-screen bg-gray-50 py-8">
      <div class="max-w-2xl mx-auto bg-white rounded-xl shadow-lg p-6">
    """, unsafe_allow_html=True)

def footer():
    st.markdown("""
      </div>
    </div>
    <div class="text-center mt-8 text-gray-500">
      <p>🔒 Secure Vault v1.0 | Military-grade encryption</p>
    </div>
    """, unsafe_allow_html=True)

def main():
    main_container()
    
    st.markdown("""
    <h1 class="text-3xl font-bold text-purple-600 mb-4 flex items-center gap-2">
      <span>🔒</span> Secure Data Vault
    </h1>
    """, unsafe_allow_html=True)

    menu = ["🏠 Home", "📥 Store Data", "📤 Retrieve Data"]
    choice = st.sidebar.radio("Navigation", menu, index=0)

    if choice == "🏠 Home":
        st.markdown("""
        <div class="space-y-6">
          <div class="p-6 bg-purple-50 rounded-xl">
            <h2 class="text-xl font-semibold text-purple-700 mb-3">Features</h2>
            <ul class="list-disc pl-6 space-y-2 text-gray-600">
              <li>AES-256 Encryption</li>
              <li>PBKDF2 Key Derivation</li>
              <li>3-Strike Security Lock</li>
            </ul>
          </div>
        </div>
        """, unsafe_allow_html=True)

    elif choice == "📥 Store Data":
        st.markdown('<div class="text-xl font-medium mb-4 text-purple-600">📥 Store Sensitive Data</div>', unsafe_allow_html=True)
        
        with st.form("store_form"):
            user_data = st.text_area("Secret Data:", height=150)
            passkey = st.text_input("Passphrase:", type="password")
            
            if st.form_submit_button("🔒 Encrypt & Store"):
                if user_data and passkey:
                    encrypted = encrypt_data(user_data)
                    st.session_state.stored_data[encrypted] = {
                        "encrypted_text": encrypted,
                        "passkey_hash": hash_passkey(passkey)
                    }
                    st.success("Data securely stored!")
                    st.code(f"Encrypted Token:\n{encrypted}")
                else:
                    st.error("All fields are required!")

    elif choice == "📤 Retrieve Data":
        st.markdown('<div class="text-xl font-medium mb-4 text-purple-600">📤 Retrieve Encrypted Data</div>', unsafe_allow_html=True)
        
        with st.form("retrieve_form"):
            encrypted = st.text_area("Encrypted Token:", height=150)
            passkey = st.text_input("Passphrase:", type="password")
            
            if st.form_submit_button("🔓 Decrypt Data"):
                if encrypted and passkey:
                    if encrypted in st.session_state.stored_data:
                        entry = st.session_state.stored_data[encrypted]
                        if entry["passkey_hash"] == hash_passkey(passkey):
                            decrypted = decrypt_data(encrypted)
                            st.success("Decryption Successful!")
                            st.text_area("Decrypted Data:", value=decrypted, height=150)
                        else:
                            st.session_state.failed_attempts += 1
                            st.error(f"❌ Invalid passphrase! Attempts remaining: {3 - st.session_state.failed_attempts}")
                            
                            if st.session_state.failed_attempts >= 3:
                                st.error("🔒 System locked! Please contact admin.")
                                st.stop()
                    else:
                        st.error("Invalid encrypted token!")
                else:
                    st.error("All fields are required!")

    footer()

if __name__ == "__main__":
    main()
