# SecureDrive

**SecureDrive** transforms an ordinary USB drive into a **Zero-Trust Physical Key** with on-the-fly hardware-backed encryption. It features a modern, Apple-inspired graphical interface built with `CustomTkinter`.

## Features

- **Anti-Cloning (The ID Check):** The USB signs a random challenge with its secret Ed25519 key to prove it is the physical original, not a clone.
- **Key Unwrapping (The Password):** Your password is run through Argon2id (memory-hard, GPU resistant) to securely unlock the hidden AES-EAX Master Key.
- **On-the-Fly Encryption (The Vault):** The FUSE engine uses the Master Key to instantly scramble/unscramble files using AES-CTR as you interact with the File Manager.
- **Modern GUI Dashboard:** A sleek, fully-featured GUI (`app.py`) for managing your vault.
- **In-App Provisioning:** Erase, partition, setup, and pair a new blank USB drive directly from the GUI Setup Assistant.
- **Zero-Data-Loss Password Changes:** Securely rotate your master password. The system unwraps the AES master key and re-encrypts it with a new KEK without touching your stored data.

## System Architecture

The architecture operates across distinct security boundaries, orchestrated by `core.py`:

**1. Graphical Interface (`app.py`)**
A macOS-style dashboard providing a visual Hero status view, an interactive File Manager (`/mnt/unlocked_vault`), and seamless password modals. It communicates with the backend daemon via a responsive thread queue.

**2. Cryptographic Daemon (`core.py`)**
The heart of the system orchestrating the security protocol:
*   **Hardware Authenticator:** A `pyudev` monitor detects drive insertion and initiates a cryptographic handshake, requesting an Ed25519 signature of a random nonce.
*   **Key Derivation:** Feeds your password into an Argon2id KDF to generate a Key Encryption Key (KEK) which decrypts `vault_header.json` to extract the 256-bit AES Master Key.
*   **FUSE Encrypted Vault:** The Master Key powers the AES-CTR Crypto Engine (`SecurePassportFS`). It intercepts read/write requests, performing stream encryption before flushing data to the raw USB storage.

**3. USB Drive Partitioning**
The drive is partitioned during provisioning:
*   **Partition 1 (`SDP_BOOT`, FAT32):** Contains the public/private identity keys (`device.cert`, `identity.key`) and the encrypted master key envelope (`vault_header.json`).
*   **Partition 2 (Data Vault, ext4):** Contains the `encrypted_vault.bin`.

## Requirements (Linux)

You need the FUSE kernel module, `udev`, and system partitioning tools (`parted`, `wipefs`, `mkfs.vfat`, `mkfs.ext4`).
On Debian/Ubuntu:
```bash
sudo apt-get update
sudo apt-get install libfuse-dev fuse parted util-linux dosfstools
```

### Python Dependencies
Install the required packages using `pip`:
```bash
pip install -r requirements.txt
```

*(Requirements include `customtkinter`, `pyudev`, `pynacl`, `pycryptodome`, `argon2-cffi`, and `fusepy`)*

## Usage

**1. Launch the Application**
SecureDrive requires root privileges for raw device access, FUSE loop mounting, and formatting capabilities. If using a desktop environment like Wayland or X11, you must preserve the environment variables for the GUI to render.
```bash
sudo -E python app.py
```

**2. Provision a New Drive**
*   Click **Provision Drive** in the sidebar.
*   Select your target USB drive (Warning: All data will be erased).
*   Set a Secure Master Password.
*   The system will automatically partition the drive, layout the filesystem, generate the Ed25519 Identity keys, and encrypt the Vault Header.

**3. Accessing the Vault**
*   Remove and re-insert the USB drive.
*   The Home Dashboard will detect the drive and run the hardware Anti-Cloning check.
*   Enter your Master Password to unwrap the AES key.
*   The **File Manager** will open. You can now seamlessly drag-and-drop, create folders, or launch a root terminal directly inside your secure vault.

## Legacy CLI Tools
The original CLI proof-of-concept scripts have been archived in the `/cli/` directory.

## Security Disclaimer
This project is an advanced proof-of-concept demonstrating software-simulated hardware secure elements. 
The Vault FUSE bridge uses AES-CTR for high-performance stream encryption on arbitrary chunk sizes. The "Factory Root Key" used for identity wrapping is hardcoded for demonstration purposes.

*For educational and experimental use.*
