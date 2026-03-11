import json
from nacl.signing import SigningKey
from nacl.encoding import HexEncoder
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def generate_device_identity():
    print("Generating Ed25519 Keypair...")
    # Generate the unique cryptographic identity for the device
    private_key = SigningKey.generate()
    public_key = private_key.verify_key

    # Simulate the "Factory Master Key" used to protect the identity on the MVP
    # In a real scenario, this is managed by the Control Plane.
    factory_key = b"0123456789abcdef0123456789abcdef"  # 32 bytes

    print("Encrypting Private Key (Simulating Secure Element)...")
    cipher = AES.new(factory_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(private_key.encode(encoder=HexEncoder))

    encrypted_identity = {
        "nonce": cipher.nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "tag": tag.hex(),
    }

    # Write the files
    with open("identity.key", "w") as f:
        json.dump(encrypted_identity, f)

    with open("device.cert", "w") as f:
        # MVP Simplification: Storing the raw public key hex as the "certificate"
        f.write(public_key.encode(encoder=HexEncoder).decode("utf-8"))

    print("Success! Created 'identity.key' and 'device.cert'.")


if __name__ == "__main__":
    generate_device_identity()
