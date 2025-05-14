import os
import json
import random
import string
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import sha256
from getpass import getpass


def generate_password(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte AES key from a password using SHA-256."""
    key = sha256(password.encode() + salt).digest()
    return urlsafe_b64encode(key)  

def encrypt_data(data: str, password: str) -> bytes:
    """Encrypt JSON data using AES-256 (Fernet)."""
    salt = os.urandom(16)  
    key = derive_key(password, salt)
    cipher = Fernet(key)
    encrypted_data = cipher.encrypt(data.encode())
    return salt + encrypted_data  

def decrypt_data(encrypted_data: bytes, password: str) -> str:
    """Decrypt data using the master password."""
    salt = encrypted_data[:16]  # Extract salt
    ciphertext = encrypted_data[16:]
    key = derive_key(password, salt)
    cipher = Fernet(key)
    return cipher.decrypt(ciphertext).decode()

def save_encrypted(data: dict, file_path: str, password: str):
    """Save data as encrypted JSON."""
    json_str = json.dumps(data, indent=4)
    encrypted = encrypt_data(json_str, password)
    with open(file_path, 'wb') as f:
        f.write(encrypted)

def load_encrypted(file_path: str, password: str) -> dict:
    """Load and decrypt JSON data."""
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    decrypted_str = decrypt_data(encrypted_data, password)
    return json.loads(decrypted_str)

def main():
    master_password = getpass("Enter your master password: ")
    
    encrypted_file = "passwords.enc"

    try:
        storage = load_encrypted(encrypted_file, master_password)
    except (FileNotFoundError, json.JSONDecodeError):
        storage = {}
    except Exception as e:
        print("⚠️ Wrong password or corrupted file!")
        return

    account_name = input("Type your account URL: ")
    length = int(input("How many symbols you want in your password? Enter only digits... "))
    new_password = generate_password(length)

    storage = {
    'account' : {
        'account name' : account_name,
        'password' : new_password
    }
}
    #storage[account_name] = new_password

    save_encrypted(storage, encrypted_file, master_password)
    print(f"✅ Password for {account_name} saved securely!")

def view_passwords():
    master_password = getpass("Enter master password: ")
    try:
        data = load_encrypted("passwords.enc", master_password)
        print("🔐 Your passwords:")
        for account, password in data.items():
            print(f"🌐 {account}: {password}")
    except Exception:
        print("❌ Wrong password or corrupted file!")



if __name__ == "__main__":
    user_selection = str(input("Do you want to create new password? [Answer Yes/No] ")).lower()
    if user_selection == "yes":
        main()
    elif user_selection == "no":
        show_passwords = str(input("You want to decrypt your existing passwords? [Answer Yes/No] ")).lower()
        if show_passwords == "yes":
            view_passwords()
        else:
            print("If you don't want to add new or view existing passwords, than Good Bye and see you soon!")