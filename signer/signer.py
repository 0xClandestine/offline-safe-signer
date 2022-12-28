# External dependencies
from eth_account import Account

# Native dependencies
from hexbytes import HexBytes
import subprocess

"""
The Signer class allows signing Ethereum transactions and printing their signatures as QR codes.
"""
class Signer:
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