from getpass import getpass

def view_passwords():
    master_password = getpass("Enter master password: ")
    try:
        data = load_encrypted("passwords.enc", master_password)
        print("🔐 Your passwords:")
        for account, password in data.items():
            print(f"🌐 {account}: {password}")
    except Exception:
        print("❌ Wrong password or corrupted file!")

view_passwords()