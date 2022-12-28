from os import system
from helpers import SafeSigner, KeystoreHelper

# Parse safe tx hash from user
safe_tx_hash = input("Enter safe tx hash: ")

# Parse keystore path from user
keystore_path = input("Enter keystore path: ")

# Parse keystore password from user
keystore_password = input("Enter keystore password: ")

# Clear user input before generating QR code, use 'cls' for windows
system('clear')

# Parse private key using user input
private_key = KeystoreHelper(keystore_path).decrypt(keystore_password)

# Sign tx hash with private key
SafeSigner(private_key).sign_and_print_qr(safe_tx_hash)