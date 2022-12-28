from os import system, name
from helpers import KeystoreHelper

# Parse private key from user
private_key = input("Enter private key: ")

# Parse keystore path from user
keystore_path = input("Enter keystore path: ")

# Parse keystore password from user
keystore_password = input("Enter keystore password: ")

# Clear user input before generating keystore
system("cls" if name == "nt" else "clear")

# Generate keystore for private key using user input
KeystoreHelper(keystore_path).encrypt(private_key, keystore_password)

# Tell user where file was saved
print("Keystore has been saved at {}", keystore_path)