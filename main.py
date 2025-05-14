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
    salt = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    key = derive_key(password, salt)
    cipher = Fernet(key)
    return cipher.decrypt(ciphertext).decode()

def init_storage(master_password: str) -> dict:
    return {
        "master_password_hash": sha256(master_password.encode()).hexdigest(),
        "accounts": {}
    }

def get_password_file(master_password: str) -> str:
    """Generate a unique filename based on password hash"""
    hash_part = sha256(master_password.encode()).hexdigest()[:8]
    return f"passwords_{hash_part}.enc"

def save_passwords(data: dict, master_password: str):
    encrypted = encrypt_data(json.dumps(data), master_password)
    file_path = get_password_file(master_password)
    with open(file_path, 'wb') as f:
        f.write(encrypted)

def load_passwords(master_password: str) -> dict:
    file_path = get_password_file(master_password)
    try:
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
    except FileNotFoundError:
        return None
    
    decrypted = decrypt_data(encrypted_data, master_password)
    data = json.loads(decrypted)
    
    stored_hash = data.get("master_password_hash")
    current_hash = sha256(master_password.encode()).hexdigest()
    if stored_hash != current_hash:
        raise ValueError("❌ Wrong master password!")
    
    return data

def main():
    master_password = getpass("Enter your master password: ")
    
    # Try loading existing data
    storage = load_passwords(master_password)
    if storage:
        print("🔓 Successfully unlocked!")
        print("\n🔐 All accounts under this master password:")
        for account, password in storage["accounts"].items():
            print(f"🌐 {account}: {password}")
    else:
        print("🆕 Creating new password storage...")
        storage = init_storage(master_password)

    # Add new account
    account_name = input("\nEnter account URL: ")
    length = int(input("How many symbols do you want to have in your password? Enter only digits... "))
    new_password = generate_password(length)
    storage["accounts"][account_name] = new_password

    # Save changes
    save_passwords(storage, master_password)
    print(f"\n✅ Password for {account_name} saved!")

    # Show all accounts again including the new one
    print("\n🔐 All accounts under this master password:")
    for account, password in storage["accounts"].items():
        print(f"🌐 {account}: {password}")

def view_all_passwords():
    master_password = getpass("Enter master password: ")
    try:
        data = load_passwords(master_password)
        if not data:
            print("No password file found for this master password.")
            return
        print("\n🔐 All accounts under this master password:")
        for account, password in data["accounts"].items():
            print(f"🌐 {account}: {password}")
    except Exception as e:
        print(e)

if __name__ == "__main__":
    user_selection = str(input("Do you want to create new password? [Answer Yes/No] ")).lower()
    if user_selection == "yes":
        main()
    elif user_selection == "no":
        show_passwords = str(input("You want to decrypt your existing passwords? [Answer Yes/No] ")).lower()
        if show_passwords == "yes":
            view_all_passwords()
        else:
            print("If you don't want to add new or view existing passwords, than Good Bye and see you soon!")