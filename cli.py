import argparse
from os import system, name
from signer import Keystore, Signer

def main():
    # Create parser
    parser = argparse.ArgumentParser(description="Generate keystore or sign tx hash")

    # Add mutual exclusive group
    group = parser.add_mutually_exclusive_group(required=True)

    # Add generate keystore option
    group.add_argument("--generate-keystore", nargs=3, metavar=("KEYSTORE_PATH", "PRIVATE_KEY", "KEYSTORE_PASSWORD"), help="Generate keystore for private key")

    # Add sign tx hash option
    group.add_argument("--sign-tx-hash", nargs=3, metavar=("KEYSTORE_PATH", "KEYSTORE_PASSWORD", "SAFE_TX_HASH"), help="Sign tx hash with private key from keystore")

    # Parse arguments
    args = parser.parse_args()

    # Clear user input
    system("cls" if name == "nt" else "clear")

    # Check which option was chosen
    if args.generate_keystore:
        keystore_path, private_key, keystore_password = args.generate_keystore
        # Generate keystore for private key using user input
        Keystore(keystore_path).encrypt(private_key, keystore_password)

        # Tell user where file was saved
        print("Keystore has been saved at:", keystore_path)
    else:
        keystore_path, keystore_password, safe_tx_hash = args.sign_tx_hash
        # Parse private key using user input
        private_key = Keystore(keystore_path).decrypt(keystore_password)

        # Sign tx hash with private key
        Signer(private_key).sign_and_print_qr(safe_tx_hash)

if __name__ == "__main__":
    main()