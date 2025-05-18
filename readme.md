# 🔐 Secure Password Manager & Generator

A simple yet secure password manager that generates strong random passwords and stores them encrypted with AES-256 encryption. Your passwords are protected by a master password that only you know.

## 🌟 Features

- **Military-grade encryption: Uses AES-256 (Fernet) to encrypt all your passwords**
- **Secure password generation: Creates cryptographically strong random passwords**
- **Master password protection: All data is encrypted with your master password**
- **Unique storage per user: Each master password creates its own encrypted file**
- **Tamper protection: Detects if wrong master password is entered**
- **No internet connection required: Everything runs locally on your machine**

## ⚙️ Installation

1. Clone this repository:  
```python
git clone https://github.com/yourusername/password-manager.git
cd password-manager
```  
2. Install the required dependencies:
```python
pip install cryptography
```  
## 🚀 Usage
Run the program:
```python
python main.py
```  
You'll be prompted to choose between:  
`Create`: Generate and store a new password  
`Check`: View all your stored passwords  

**Creating a new password entry:**
1. Enter your master password (this won't be displayed as you type)  
2. Enter the account/website name(URL)  
3. Specify how long you want the password to be  
4. Your new secure password will be generated and stored automatically  

**Viewing stored passwords:**  
1. Enter your master password  
2. All your stored accounts and passwords will be displayed  

## 🔒 Security Details  
- **Encryption**: Uses AES-256 via Fernet (symmetric encryption)  
- **Key derivation**: SHA-256 with random salt for key stretching  
- **Password generation**: Cryptographically secure random characters  
- **Data integrity**: Master password hash verification prevents tampering  

## 📁 File Storage
Your passwords are stored in an encrypted file named `passwords_[hash].enc` where `[hash]` is derived from your master password. This means:  
1. **Never lose your master password** - Without it, your passwords cannot be recovered  
2. **Don't share your master password** - Anyone with it can decrypt your passwords  
3. **Keep backups** - Consider backing up your encrypted password file  
4. **Use a strong master password** - At least 12 characters with mix of letters, numbers and symbols  

## 📝 License  
This project is open source and available under the MIT License.  

## 🤝 Contributing
Contributions are welcome! Please open an issue or pull request for any improvements.  

**💡 Tip**: For maximum security, consider using this on a secure personal computer rather than shared machines.