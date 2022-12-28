from os import system, name
from signer import Signer, Keystore

# Parse safe tx hash from user
safe_tx_hash = input("Enter safe tx hash: ")

# Parse keystore path from user
keystore_path = input("Enter keystore path: ")

# Parse keystore password from user
keystore_password = input("Enter keystore password: ")

# Clear user input before generating QR code
system("cls" if name == "nt" else "clear")

# Parse private key using user input
private_key = Keystore(keystore_path).decrypt(keystore_password)

# Sign tx hash with private key
Signer(private_key).sign_and_print_qr(safe_tx_hash)