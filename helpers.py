from json import dump, load
from qrcode import QRCode
from eth_account import Account
from hexbytes import HexBytes

class SafeSigner:
    def __init__(self, private_key: str):
        self.private_key = private_key
        self.account = Account.from_key(self.private_key)

    def sign(self, safe_tx_hash: HexBytes) -> bytes:
        signature_dict = self.account.signHash(safe_tx_hash)
        v, r, s = signature_dict["v"], signature_dict["r"], signature_dict["s"]
        return r.to_bytes(32, "big") + s.to_bytes(32, "big") + v.to_bytes(1, "big")

    def sign_and_print_qr(self, safe_tx_hash: str):
        safe_tx_hash = safe_tx_hash[2:] if safe_tx_hash[:2] == "0x" else safe_tx_hash
        signature = HexBytes(self.sign(HexBytes(safe_tx_hash))).hex()
        print("Signature: \n", signature, "\n")
        qr = QRCode()
        qr.add_data(signature)
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