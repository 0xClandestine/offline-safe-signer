# External dependencies
from eth_account import Account

# Native dependencies
from json import dump, load
from hexbytes import HexBytes
import subprocess

"""
The SafeSigner class allows signing Ethereum transactions and printing their signatures as QR codes.
"""
class SafeSigner:
    def __init__(self, private_key: str):
        """
        Initializes the SafeSigner object with a private key.

        Parameters:
        private_key (str): The private key to use for signing Ethereum transactions.
        """
        # Store the private key
        self.private_key = private_key
        # Initialize an Ethereum account object from the private key
        self.account = Account.from_key(self.private_key)

    def sign(self, safe_tx_hash: HexBytes) -> bytes:
        """
        Signs an Ethereum transaction hash and returns the signature.

        Parameters:
        safe_tx_hash (HexBytes): The transaction hash to sign.

        Returns:
        bytes: The signature of the transaction hash.
        """
        # Sign the transaction hash using the Ethereum account object
        signature_dict = self.account.signHash(safe_tx_hash)
        # Extract the v, r, and s values from the signature dictionary
        v, r, s = signature_dict["v"], signature_dict["r"], signature_dict["s"]
        # Concatenate the r, s, and v values and return them as bytes
        return r.to_bytes(32, "big") + s.to_bytes(32, "big") + v.to_bytes(1, "big")

    def sign_and_print_qr(self, safe_tx_hash: str):
        """
        Signs an Ethereum transaction hash, and prints the signature as a QR code.

        Parameters:
        safe_tx_hash (str): The transaction hash to sign.
        """
        # If the transaction hash is prefixed with "0x", remove the prefix
        safe_tx_hash = safe_tx_hash[2:] if safe_tx_hash[:2] == "0x" else safe_tx_hash
        # Sign the transaction hash and convert the signature to a hexadecimal string
        signature = HexBytes(self.sign(HexBytes(safe_tx_hash))).hex()
        # Print the signature
        print("Signature: \n", signature, "\n")
        # Use python3-qrcode (built into tails) to create and display qr code
        subprocess.call("qr {0}".format(signature), shell=True)

class KeystoreHelper:
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
            dump(keystore, f)

    def decrypt(self, password):
        """Decrypt the private key from the keystore file.

        Args:
            password: The password used to encrypt the private key.

        Returns:
            The decrypted private key, as a hexadecimal string.
        """
        # Read the keystore from the keystore file
        with open(self.keystore_path, "r") as f:
            keystore = load(f)
        # Decrypt the keystore with the given password
        private_key = Account.decrypt(keystore, password)
        # Return the decrypted private key as a hexadecimal string
        return private_key.hex()

    def generate_private_key():
        """Generate a new random private key.

        Returns:
            The private key, as a hexadecimal string.
        """
        # Create a new Account object with a randomly generated private key
        private_key = Account.create().privateKey
        # Return the private key as a hexadecimal string
        return private_key.hex()