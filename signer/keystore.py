# External dependencies
from eth_account import Account

# Native dependencies
import json

class Keystore:
    def __init__(self, keystore_path):
        """Initialize a KeystoreHelper with the path to a keystore file."""
        self.keystore_path = keystore_path

    def encrypt(self, private_key, password):
        """Encrypt a private key and save it to the keystore file.

        Args:
            private_key: The private key to encrypt, as a hexadecimal string.
            password: The password to use for encrypting the private key.
        """
        # Convert the private key to an Account object
        account = Account.privateKeyToAccount(private_key)
        # Encrypt the account with the given password
        keystore = account.encrypt(password)
        # Write the encrypted keystore to the keystore file
        with open(self.keystore_path, "w") as f:
            json.dump(keystore, f)

    def decrypt(self, password):
        """Decrypt the private key from the keystore file.

        Args:
            password: The password used to encrypt the private key.

        Returns:
            The decrypted private key, as a hexadecimal string.
        """
        # Read the keystore from the keystore file
        with open(self.keystore_path, "r") as f:
            keystore = json.load(f)
        # Decrypt the keystore with the given password
        private_key = Account.decrypt(keystore, password)
        # Return the decrypted private key as a hexadecimal string
        return private_key.hex()