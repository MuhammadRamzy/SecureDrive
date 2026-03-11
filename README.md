# SecureDrive Passport

**SecureDrive** transforms an ordinary USB drive into a **Zero-Trust Physical Key** with on-the-fly hardware-backed encryption.

## How It Works (The Absolute Shortest Explanation)

1. **Anti-Cloning (The ID Check):** The USB signs a random challenge with its secret Ed25519 key to prove it is the physical original, not a clone.
2. **Key Unwrapping (The Password):** Your password is run through Argon2id (to block supercomputers) to securely unlock the hidden AES Master Key.
3. **On-the-Fly Encryption (The Vault):** The FUSE engine uses that Master Key to instantly scramble/unscramble files (using AES-CTR) as you drag and drop them.

## Structure

*   `passport.py`: The main daemon that listens for USB insertion, handles the Zero-Trust handshake, derives keys, and mounts the FUSE encrypted filesystem.
*   `genIDKey.py`: A utility to generate the initial Ed25519 identity keypair simulating the factory provisioning of a hardware secure element.

## Prerequisites (Linux)

You will need the following Python libraries. Install them via `pip`:

```bash
pip install -r requirements.txt
```

You also need the FUSE development headers and a running udev daemon.
On Debian/Ubuntu:
```bash
sudo apt-get install libfuse-dev fuse
```

## Setup & Usage

1.  **Initial Provisioning (Simulation):** 
    In a real-world scenario, the factory generates the key. For this MVP, run the generation script to create `identity.key` and `device.cert`.
    ```bash
    python genIDKey.py
    ```
    *Note: These files must be placed on the boot partition of your "SecureDrive" USB.*

2.  **Running the Daemon:**
    Run the `passport.py` script as `root` (required for raw block device access and FUSE mounting).
    ```bash
    sudo python passport.py
    ```

3.  **Operation:**
    *   Insert your formatted USB Drive (Labelled `SDP_BOOT`).
    *   The daemon detects the insertion and initiates the Zero-Trust Handshake.
    *   It verifies the hardware identity (Anti-Cloning).
    *   You are prompted for your password to unwrap the AES master key.
    *   Once authenticated, a virtual, encrypted vault is mounted at `/mnt/unlocked_vault`.
    *   Saving files into `/mnt/unlocked_vault` encrypts them instantly and writes them to the underlying USB drive.
    *   Removing the drive aggressively tears down the cryptographic boundary and unmounts the FUSE filesystem.

## Security Considerations (MVP Status)

*   This project is a functional MVP simulating hardware secure elements. 
*   The "Factory Master Key" is hardcoded in the MVP for simplicity and should be protected by a true hardware TPM/Secure Element in production.
*   The FUSE vault uses AES-CTR for high-performance stream encryption on arbitrary chunk sizes.

## Disclaimer
This project is for educational and proof-of-concept purposes. 
