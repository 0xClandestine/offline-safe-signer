from json import dump, load
from hexbytes import HexBytes
from qrcode import QRCode
from eth_account import Account

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
        Signs an Ethereum transaction hash, prints the signature as a QR code, and returns the signature.

        Parameters:
        safe_tx_hash (str): The transaction hash to sign.

        Returns:
        str: The signature of the transaction hash.
        """
        # If the transaction hash is prefixed with "0x", remove the prefix
        safe_tx_hash = safe_tx_hash[2:] if safe_tx_hash[:2] == "0x" else safe_tx_hash
        # Sign the transaction hash and convert the signature to a hexadecimal string
        signature = HexBytes(self.sign(HexBytes(safe_tx_hash))).hex()
        # Print the signature
        print("Signature: \n", signature, "\n")
        # Initialize a QR code object
        qr = QRCode()
        # Add the signature to the QR code
        qr.add_data(signature)
        # Print the QR code as ASCII art
        qr.print_ascii()

class KeystoreHelper:
    def __init__(self, keystore_path):
        self.keystore_path = keystore_path

    def encrypt(self, private_key, password):
        account = Account.privateKeyToAccount(private_key)
        keystore = account.encrypt(password)
        with open(self.keystore_path, "w") as f:
            dump(keystore, f)

    def decrypt(self, password):
        with open(self.keystore_path, "r") as f:
            keystore = load(f)
        private_key = Account.decrypt(keystore, password)
        return private_key.hex()

    def generate_private_key():
        private_key = Account.create().privateKey
        return private_key.hex()