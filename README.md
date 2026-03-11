# SecureDrive Passport

![SecureDrive System Diagram](Image.png)

**SecureDrive** transforms an ordinary USB drive into a **Zero-Trust Physical Key** with on-the-fly hardware-backed encryption.

## How It Works (The Absolute Shortest Explanation)

1. **Anti-Cloning (The ID Check):** The USB signs a random challenge with its secret Ed25519 key to prove it is the physical original, not a clone.
2. **Key Unwrapping (The Password):** Your password is run through Argon2id (to block supercomputers) to securely unlock the hidden AES Master Key.
3. **On-the-Fly Encryption (The Vault):** The FUSE engine uses that Master Key to instantly scramble/unscramble files (using AES-CTR) as you drag and drop them.

## Technical Architecture & Zero-Trust Workflow

As illustrated in the system diagram above, the SecureDrive architecture operates across four distinct security boundaries:

**1. Userspace (User Application)**
*   Everyday applications (e.g., File Manager) interact with the vault transparently. They read and write cleartext data (`hello.txt`) to the mounted folder (`/mnt/unlocked_vault`), completely unaware of the underlying cryptographic engine.

**2. Privileged Space (Runtime Daemon: `passport.py`)**
This is the heart of the system, orchestrating the security protocol in three phases:
*   **Phase 1: Hardware Authenticator (Anti-Cloning):** A `udev` event interceptor detects the drive insertion. It initiates a challenge-response handshake, sending a random nonce (N) to the USB. The drive must sign this nonce using its hidden Ed25519 private key to prove physical possession against clones.
*   **Phase 2: Key Derivation & Unwrapping (User Auth):** Your password is fed into a memory-hard Argon2id Key Derivation Function (KDF) to generate a Key Encryption Key (KEK). The Unwrapping Engine uses this KEK to decrypt the `vault_header.json`, securely extracting the 256-bit AES Master Key.
*   **Phase 3: FUSE Encrypted Vault (Data Protection):** The extracted Master Key powers the AES-CTR Crypto Engine (`_crypt`). It intercepts user read/write requests and performs synchronous, on-the-fly stream encryption before passing data to the FUSE bridge.

**3. Kernel Space (OS Subsystems)**
*   The Linux kernel manages the physical hardware connections. The `udev` subsystem handles insertion events, while the Virtual Filesystem (VFS) and FUSE Kernel Module coordinate the sector-aligned reads and writes between the crypto daemon and the raw USB storage.

**4. USB Drive (Physical Storage)**
The drive itself is deeply segmented into two distinct partitions:
*   **Partition 1 (`SDP_BOOT`, FAT32):** Contains the public/private identity keys (`device.cert`, `identity.key`) and the encrypted master key envelope (`vault_header.json`). This partition handles the control and authentication logic.
*   **Partition 2 (Data Vault, /dev/sdX2):** A raw block device containing `encrypted_vault.bin`. Without the passport daemon, this partition contains nothing but cryptographic gibberish.

## Repository Structure

*   `passport.py`: The main daemon executing the Privileged Space logic.
*   `genIDKey.py`: A utility simulating the factory provisioning of the identity keys.

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
