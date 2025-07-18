# Required packages for the Password Manager
# Install these packages using: pip install -r requirements.txt

required_packages = [
    "cryptography>=3.4.8",  # For encryption/decryption
    "pyperclip>=1.8.2",     # For clipboard operations
]

print("Required packages for Password Manager:")
for package in required_packages:
    print(f"  - {package}")

print("\nTo install all requirements, run:")
print("pip install cryptography pyperclip")
