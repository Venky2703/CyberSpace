import json
import base64
import hashlib
import streamlit as st
from cryptography.fernet import Fernet
from hashlib import sha256

# Function to generate a key and save it into a file
def generate_key():
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)

# Function to load the key
def load_key():
    return open("key.key", "rb").read()

# Function to encrypt a message
def encrypt_message(message, method, key=None, shift=3, keyword=None):
    if method == "Caesar Cipher":
        return ''.join(
            chr((ord(char) - 65 + shift) % 26 + 65) if char.isupper() else
            chr((ord(char) - 97 + shift) % 26 + 97) if char.islower() else char
            for char in message
        )
    elif method == "Base64":
        return base64.b64encode(message.encode()).decode()
    elif method == "Hex":
        return message.encode().hex()
    elif method == "ROT13":
        return message.translate(str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
        ))
    elif method == "Reverse":
        return message[::-1]
    elif method == "SHA-256 Hash":
        return sha256(message.encode()).hexdigest()
    elif method == "MD5 Hash":
        return hashlib.md5(message.encode()).hexdigest()
    elif method == "Fernet Encrypt/Decrypt" and key:
        f = Fernet(key)
        encrypted_message = f.encrypt(message.encode())
        return base64.urlsafe_b64encode(encrypted_message).decode('utf-8')
    elif method == "Vigenère Cipher" and keyword:
        keyword_repeated = (keyword * (len(message) // len(keyword) + 1))[:len(message)]
        return ''.join(
            chr((ord(t) + ord(k) - 2 * ord('A')) % 26 + ord('A')) if t.isupper() else
            chr((ord(t) + ord(k) - 2 * ord('a')) % 26 + ord('a')) if t.islower() else t
            for t, k in zip(message, keyword_repeated)
        )
    else:
        return None

# Function to decrypt a message
def decrypt_message(encrypted_message, method, key=None, shift=3, keyword=None):
    if method == "Caesar Cipher":
        return ''.join(
            chr((ord(char) - 65 - shift) % 26 + 65) if char.isupper() else
            chr((ord(char) - 97 - shift) % 26 + 97) if char.islower() else char
            for char in encrypted_message
        )
    elif method == "Base64":
        try:
            return base64.b64decode(encrypted_message.encode()).decode('utf-8', errors='ignore')
        except Exception as e:
            return str(e)
    elif method == "Hex":
        try:
            return bytes.fromhex(encrypted_message).decode('utf-8', errors='ignore')
        except Exception as e:
            return str(e)
    elif method == "ROT13":
        return encrypted_message.translate(str.maketrans(
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        ))
    elif method == "Reverse":
        return encrypted_message[::-1]
    elif method == "Fernet Encrypt/Decrypt" and key:
        try:
            f = Fernet(key)
            decrypted_message = f.decrypt(base64.urlsafe_b64decode(encrypted_message.encode('utf-8')))
            return decrypted_message.decode()
        except Exception as e:
            return str(e)
    elif method == "Vigenère Cipher" and keyword:
        keyword_repeated = (keyword * (len(encrypted_message) // len(keyword) + 1))[:len(encrypted_message)]
        return ''.join(
            chr((ord(t) - ord(k) - 2 * ord('A')) % 26 + ord('A')) if t.isupper() else
            chr((ord(t) - ord(k) - 2 * ord('a')) % 26 + ord('a')) if t.islower() else t
            for t, k in zip(encrypted_message, keyword_repeated)
        )
    else:
        return None

# Password manager class
class PasswordManager:
    def __init__(self, key):
        self.key = key
        self.passwords = self.load_passwords()

    def add_password(self, service, password):
        encrypted_password = encrypt_message(password, "Fernet Encrypt/Decrypt", self.key)
        self.passwords[service] = encrypted_password
        self.save_passwords()

    def get_password(self, service):
        encrypted_password = self.passwords.get(service)
        if encrypted_password:
            return decrypt_message(encrypted_password, "Fernet Encrypt/Decrypt", self.key)
        return None

    def save_passwords(self):
        with open("passwords.json", "w") as f:
            json.dump(self.passwords, f)

    def load_passwords(self):
        try:
            with open("passwords.json", "r") as f:
                passwords = json.load(f)
            return passwords
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

# Generate and load key if it doesn't already exist
try:
    key = load_key()
except FileNotFoundError:
    generate_key()
    key = load_key()

# Create an instance of PasswordManager
manager = PasswordManager(key)

# Streamlit Sidebar for Navigation
st.sidebar.title("Navigation")
selection = st.sidebar.selectbox("Go to", ["Password Manager", "Text to Cipher"])

# Title
st.title("Cyberspace")

# Password Manager Section
if selection == "Password Manager":
    st.header("Password Manager")

    # Add password section
    st.subheader("Add a New Password")
    service = st.text_input("Service")
    password = st.text_input("Password", type="password")
    if st.button("Add Password"):
        if service and password:
            manager.add_password(service, password)
            st.success(f"Password for {service} added successfully!")
        else:
            st.error("Please provide both service and password.")

    # Get password section
    st.subheader("Retrieve a Password")
    service_query = st.text_input("Service to Retrieve")
    if st.button("Get Password"):
        if service_query:
            retrieved_password = manager.get_password(service_query)
            if retrieved_password:
                st.info(f"The password for {service_query} is: {retrieved_password}")
            else:
                st.warning(f"No password found for {service_query}.")
        else:
            st.error("Please provide the service name.")

# Text to Cipher Section
elif selection == "Text to Cipher":
    st.header("Text to Cipher")

    # Text input
    plain_text = st.text_area("Enter the plain text")
    cipher_text = st.text_area("Enter the cipher text for decryption")

    # Encryption and Decryption Methods
    st.subheader("Encryption and Decryption Methods")
    method = st.selectbox("Select Method", ["Caesar Cipher", "Base64", "Hex", "ROT13", "Reverse", "SHA-256 Hash", "MD5 Hash", "Fernet Encrypt/Decrypt", "Vigenère Cipher"])

    # Additional Inputs for Specific Methods
    shift = None
    keyword = None
    if method == "Caesar Cipher":
        shift = st.slider("Shift", 1, 25, 3)
    elif method == "Vigenère Cipher":
        keyword = st.text_input("Keyword")

    # Encryption
    if plain_text:
        encrypted_text = encrypt_message(plain_text, method, key, shift, keyword)
        st.text_area(f"{method} Encrypted Text", encrypted_text, height=150)

    # Decryption
    if cipher_text:
        decrypted_text = decrypt_message(cipher_text, method, key, shift, keyword)
        st.text_area(f"{method} Decrypted Text", decrypted_text, height=150)
