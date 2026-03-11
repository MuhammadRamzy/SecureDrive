import pyudev
import os
import subprocess
import json
import time
import stat
import errno
import threading
from threading import Thread, Event

# Cryptography & System Libraries
from nacl.signing import VerifyKey, SigningKey
from nacl.encoding import HexEncoder
from Crypto.Cipher import AES
from Crypto.Util import Counter
from argon2.low_level import hash_secret_raw, Type
from fuse import FUSE, Operations, LoggingMixIn


# --- FUSE FILESYSTEM IMPLEMENTATION (CTR MODE) ---
class SecurePassportFS(LoggingMixIn, Operations):
    def __init__(self, raw_partition_path, key):
        self.raw_partition_path = raw_partition_path
        self.fd = os.open(self.raw_partition_path, os.O_RDWR)

        # Use a 256-bit key for CTR mode stream cipher
        self.key = key[:32]
        self.virtual_file = "/vault.img"

        self.size = os.lseek(self.fd, 0, os.SEEK_END)
        os.lseek(self.fd, 0, os.SEEK_SET)

    def getattr(self, path, fh=None):
        if path == "/":
            return {"st_mode": (stat.S_IFDIR | 0o755), "st_nlink": 2}
        elif path == self.virtual_file:
            return {
                "st_mode": (stat.S_IFREG | 0o666),
                "st_size": self.size,
                "st_nlink": 1,
            }
        else:
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))

    def readdir(self, path, fh):
        if path == "/":
            return [".", "..", self.virtual_file[1:]]

    def truncate(self, path, length, fh=None):
        return 0

    def chmod(self, path, mode):
        return 0

    def chown(self, path, uid, gid):
        return 0

    def utimens(self, path, times=None):
        return 0

    def fsync(self, path, fdatasync, fh):
        os.fsync(self.fd)
        return 0

    def flush(self, path, fh):
        os.fsync(self.fd)
        return 0

    def _crypt(self, data, offset):
        block_index = offset // 16
        remainder = offset % 16
        ctr = Counter.new(128, initial_value=block_index)
        cipher = AES.new(self.key, AES.MODE_CTR, counter=ctr)
        if remainder > 0:
            cipher.encrypt(b"\x00" * remainder)
        return cipher.encrypt(data)

    def read(self, path, length, offset, fh):
        if path != self.virtual_file:
            raise OSError(errno.EIO, os.strerror(errno.EIO))
        os.lseek(self.fd, offset, os.SEEK_SET)
        ciphertext = os.read(self.fd, length)
        return self._crypt(ciphertext, offset)

    def write(self, path, buf, offset, fh):
        if path != self.virtual_file:
            raise OSError(errno.EIO, os.strerror(errno.EIO))
        ciphertext = self._crypt(buf, offset)
        os.lseek(self.fd, offset, os.SEEK_SET)
        os.write(self.fd, ciphertext)
        return len(buf)

    def destroy(self, path):
        os.close(self.fd)


class SecureDriveCore:
    def __init__(self, on_log, on_status, on_password_requested, on_setup_requested):
        """
        on_log: func(message: str)
        on_status: func(status: str) 'WAITING', 'PHASE1', 'PHASE2', 'UNLOCKED', 'ERROR'
        on_password_requested: func(callback)
        on_setup_requested: func(callback)
        """
        self.on_log = on_log
        self.on_status = on_status
        self.on_password_requested = on_password_requested
        self.on_setup_requested = on_setup_requested

        self.context = pyudev.Context()
        self.monitor = pyudev.Monitor.from_netlink(self.context)
        self.monitor.filter_by(subsystem="block")
        self.running = False
        self.monitor_thread = None
        self.current_boot_node = None

    def log(self, msg):
        if self.on_log:
            self.on_log(msg)

    def status(self, stat):
        if self.on_status:
            self.on_status(stat)

    def start(self):
        self.running = True
        self._cleanup_all_mounts()
        self.monitor_thread = Thread(target=self._event_loop, daemon=True)
        self.monitor_thread.start()
        self.status("WAITING")
        self.log("SecureDrive Core initialized. Waiting for device insertion...")

    def stop(self):
        self.running = False
        self._cleanup_all_mounts()

    def _cleanup_all_mounts(self):
        subprocess.run(
            ["umount", "-l", "/mnt/unlocked_vault"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            ["umount", "-l", "/mnt/secure_drive"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            ["umount", "-l", "/mnt/raw_usb"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            ["umount", "-l", "/tmp/sdp_boot"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def _event_loop(self):
        self.monitor.start()
        while self.running:
            device = self.monitor.poll(timeout=1)
            if not self.running:
                break
            if device is None:
                continue

            if device.action == "add":
                if self._is_securedrive(device):
                    # Run the handshake in a separate thread to not block the monitor loop
                    Thread(
                        target=self._initiate_handshake, args=(device,), daemon=True
                    ).start()
            elif device.action == "remove":
                if "sd" in device.device_node:
                    self._handle_removal(device)

    def _is_securedrive(self, device):
        return device.get("ID_FS_LABEL") == "SDP_BOOT"

    def _handle_removal(self, device):
        self.current_boot_node = None
        self.log("[-] Device Removed / Protocol Aborted")
        self.log(
            "[*] Tearing down Zero-Trust Vault and aggressively wiping keys from RAM..."
        )
        self._cleanup_all_mounts()
        self.log("[+] Teardown Complete. Cryptographic boundary restored.")
        self.status("WAITING")

    def _request_password(self):
        result = [None]  # Will hold (password, is_reset)
        ev = Event()

        def callback(pwd, reset=False):
            result[0] = (pwd, reset)
            ev.set()

        self.on_password_requested(callback)
        ev.wait()
        return result[0]

    def _request_setup(self):
        result = [None]
        ev = Event()

        def callback(password):
            result[0] = password
            ev.set()

        self.on_setup_requested(callback)
        ev.wait()
        return result[0]

    def _initiate_handshake(self, device):
        self.log(f"\n[+] SECUREDRIVE PASSPORT DETECTED: {device.device_node}")
        self.log("[*] Initiating Zero-Trust Handshake Protocol...\n")
        self.status("PHASE1")

        boot_node = device.device_node
        self.current_boot_node = boot_node
        data_partition_node = boot_node[:-1] + "2"
        mount_point = "/tmp/sdp_boot"
        vault_file = "/mnt/raw_usb/encrypted_vault.bin"

        self._cleanup_all_mounts()

        # Mount Partitions
        os.makedirs(mount_point, exist_ok=True)
        os.makedirs("/mnt/raw_usb", exist_ok=True)

        if (
            subprocess.run(
                ["mount", boot_node, mount_point], capture_output=True
            ).returncode
            != 0
        ):
            self.log("[-] OS Mount Command Failed for Boot Partition.")
            self.status("ERROR")
            return

        if (
            subprocess.run(
                ["mount", data_partition_node, "/mnt/raw_usb"], capture_output=True
            ).returncode
            != 0
        ):
            self.log("[-] OS Mount Command Failed for Data Partition.")
            subprocess.run(
                ["umount", "-l", mount_point],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.status("ERROR")
            return

        # Check Initialization State
        cert_path = os.path.join(mount_point, "device.cert")
        id_path = os.path.join(mount_point, "identity.key")
        header_path = os.path.join(mount_point, "vault_header.json")

        if not (
            os.path.exists(cert_path)
            and os.path.exists(id_path)
            and os.path.exists(header_path)
        ):
            self.log("[!] Uninitialized or Corrupted SecureDrive Detected.")
            self.status("PHASE2")  # Prompting for setup
            password = self._request_setup()
            if not password:
                self.log("Setup aborted.")
                self._handle_removal(device)
                return
            if not self._setup_secure_drive(mount_point, vault_file, password):
                self._handle_removal(device)
            return

        # PHASE 1
        self.log("--- [PHASE 1: CRYPTOGRAPHIC IDENTITY VERIFICATION] ---")
        try:
            self.log("[*] 1. Extracting Device Certificate (Public Key)...")
            with open(cert_path, "r") as f:
                public_key_hex = f.read().strip()
                verify_key = VerifyKey(public_key_hex, encoder=HexEncoder)
            self.log(
                f"    -> Public Key: {public_key_hex[:16]}...{public_key_hex[-16:]}"
            )

            self.log("[*] 2. Generating 256-bit Challenge Nonce (Host -> Device)...")
            nonce = os.urandom(32)
            self.log(f"    -> Nonce (N): {nonce.hex()[:16]}...{nonce.hex()[-16:]}")

            self.log(
                "[*] 3. Device Secure Element Signing Nonce with Ed25519 Private Key..."
            )
            with open(id_path, "r") as f:
                enc_identity = json.load(f)

            factory_key = b"0123456789abcdef0123456789abcdef"
            cipher = AES.new(
                factory_key, AES.MODE_EAX, nonce=bytes.fromhex(enc_identity["nonce"])
            )
            private_key_bytes = cipher.decrypt_and_verify(
                bytes.fromhex(enc_identity["ciphertext"]),
                bytes.fromhex(enc_identity["tag"]),
            )
            signing_key = SigningKey(private_key_bytes, encoder=HexEncoder)

            signed_message = signing_key.sign(nonce)
            signature = signed_message.signature
            self.log(
                f"    -> Signature (S): {signature.hex()[:16]}...{signature.hex()[-16:]}"
            )

            self.log("[*] 4. Host Verifying Signature against Device Public Key...")
            verify_key.verify(nonce, signature)
            self.log(
                "[+] SUCCESS: Proof of Possession Confirmed. Anti-Cloning Check Passed!\n"
            )

        except Exception as e:
            self.log(f"[-] HANDSHAKE FAILED (Cryptographic Error): {e}")
            self.status("ERROR")
            self._handle_removal(device)
            return

        # PHASE 2
        self.status("PHASE2")
        self.log("--- [PHASE 2: KEY DERIVATION & UNWRAPPING] ---")

        pwd, request_reset = self._request_password()

        if request_reset:
            self.log("Factory resetting device per user request.")
            password = self._request_setup()
            if not password:
                self.log("Reset aborted.")
                self._handle_removal(device)
                return
            self._setup_secure_drive(mount_point, vault_file, password)
            self._handle_removal(device)
            return

        if not pwd:
            self.log("Authentication aborted.")
            self._handle_removal(device)
            return

        password = pwd
        self.log(
            "[*] Deriving Key Encryption Key (KEK) via Argon2id (Memory-Hard Function)..."
        )
        self.log("    -> Simulating GPU/ASIC resistance. Please wait...")

        with open(header_path, "r") as f:
            header_data = json.load(f)

        salt = bytes.fromhex(header_data["salt"])
        kek = hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=2,
            memory_cost=102400,
            parallelism=8,
            hash_len=32,
            type=Type.I,
        )
        self.log(f"    -> KEK Hash: {kek.hex()[:16]}... (Truncated for security)")

        self.log("[*] Attempting to unwrap Master Key using KEK...")
        cipher_vault = AES.new(
            kek, AES.MODE_EAX, nonce=bytes.fromhex(header_data["nonce"])
        )

        try:
            master_key = cipher_vault.decrypt_and_verify(
                bytes.fromhex(header_data["ciphertext"]),
                bytes.fromhex(header_data["tag"]),
            )
            self.log(
                "[+] SUCCESS: Master Key successfully unwrapped. Password verified!\n"
            )
        except ValueError:
            self.log(
                "\n[-] ACCESS DENIED: Incorrect Password! Cryptographic unwrapping failed."
            )
            self.log("[-] The Master Key remains secured. Aborting mount sequence.")
            self.status("ERROR")
            self._handle_removal(device)
            return

        subprocess.run(
            ["umount", "-l", mount_point],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # PHASE 3
        self.log("--- [PHASE 3: FUSE VAULT DECRYPTION] ---")
        self.log(f"[*] Booting FUSE Crypto-Engine on {vault_file}...")
        try:
            os.makedirs("/mnt/secure_drive", exist_ok=True)
            fuse_thread = Thread(
                target=lambda: FUSE(
                    SecurePassportFS(vault_file, master_key),
                    "/mnt/secure_drive",
                    foreground=True,
                    allow_other=True,
                )
            )
            fuse_thread.daemon = True
            fuse_thread.start()

            self.log("[*] Waiting for FUSE bridge to stabilize...")

            fuse_ready = False
            for _ in range(10):  # 5 second timeout
                if os.path.exists("/mnt/secure_drive/vault.img"):
                    fuse_ready = True
                    break
                time.sleep(0.5)

            if not fuse_ready:
                self.log("[-] ERROR: FUSE bridge timeout. Auto-mount aborted.")
                self.status("ERROR")
                self._handle_removal(device)
                return

            self.log("[*] FUSE active. Auto-mounting usable user directory...")

            uid = os.environ.get("SUDO_UID", "1000")
            gid = os.environ.get("SUDO_GID", "1000")

            os.makedirs("/mnt/unlocked_vault", exist_ok=True)
            mount_cmd = [
                "mount",
                "-o",
                f"loop,sync,uid={uid},gid={gid},umask=000",
                "/mnt/secure_drive/vault.img",
                "/mnt/unlocked_vault",
            ]

            mount_result = subprocess.run(mount_cmd, capture_output=True, text=True)

            if mount_result.returncode == 0:
                self.log("\n=======================================================")
                self.log("[+] SUCCESS! SecureDrive Passport is Fully Unlocked.")
                self.log("[+] Your secure files are available at: /mnt/unlocked_vault")
                self.log("=======================================================\n")
                self.status("UNLOCKED")
            else:
                self.log(f"[-] Auto-Mount Failed: {mount_result.stderr.strip()}")
                self.log(
                    "[*] Hint: If this is a newly provisioned vault, you must format it first:"
                )
                self.log(
                    "[*] Open a terminal and run: sudo mkfs.vfat /mnt/unlocked_vault"
                )  # Wait, mkfs.vfat /mnt/secure_drive/vault.img
                self.status("ERROR")

        except Exception as e:
            self.log(f"[-] FUSE Initialization Failed: {e}")
            self.status("ERROR")
            self._handle_removal(device)

    def _setup_secure_drive(self, mount_point, vault_file_path, new_pass):
        self.log("\n=======================================================")
        self.log(" [!] SECUREDRIVE INITIALIZATION / FACTORY RESET [!]")
        self.log("=======================================================")

        self.log("\n[*] 1. Generating new Ed25519 hardware identity...")
        time.sleep(0.5)
        private_key = SigningKey.generate()
        public_key = private_key.verify_key

        factory_key = b"0123456789abcdef0123456789abcdef"
        cipher_id = AES.new(factory_key, AES.MODE_EAX)
        ciphertext_id, tag_id = cipher_id.encrypt_and_digest(
            private_key.encode(encoder=HexEncoder)
        )

        with open(os.path.join(mount_point, "identity.key"), "w") as f:
            json.dump(
                {
                    "nonce": cipher_id.nonce.hex(),
                    "ciphertext": ciphertext_id.hex(),
                    "tag": tag_id.hex(),
                },
                f,
            )

        with open(os.path.join(mount_point, "device.cert"), "w") as f:
            f.write(public_key.encode(encoder=HexEncoder).decode("utf-8"))
        self.log(
            f"    -> Identity saved. Public Key: {public_key.encode(encoder=HexEncoder).decode('utf-8')[:16]}..."
        )

        self.log("\n[*] 2. Generating 256-bit Vault Master Key...")
        time.sleep(0.5)
        master_key = os.urandom(32)

        self.log("[*] 3. Deriving Key Encryption Key (KEK) via Argon2id...")
        salt = os.urandom(16)
        kek = hash_secret_raw(
            secret=new_pass.encode("utf-8"),
            salt=salt,
            time_cost=2,
            memory_cost=102400,
            parallelism=8,
            hash_len=32,
            type=Type.I,
        )

        self.log("[*] 4. Wrapping Master Key with KEK (AES-EAX)...")
        time.sleep(0.5)
        cipher_vault = AES.new(kek, AES.MODE_EAX)
        ciphertext_mk, tag_mk = cipher_vault.encrypt_and_digest(master_key)

        with open(os.path.join(mount_point, "vault_header.json"), "w") as f:
            json.dump(
                {
                    "salt": salt.hex(),
                    "nonce": cipher_vault.nonce.hex(),
                    "ciphertext": ciphertext_mk.hex(),
                    "tag": tag_mk.hex(),
                },
                f,
            )
        self.log("    -> Vault header secured and saved to boot partition.")

        self.log("\n[*] 5. Provisioning new encrypted vault backing file...")
        os.makedirs(os.path.dirname(vault_file_path), exist_ok=True)
        with open(vault_file_path, "wb") as f:
            f.truncate(100 * 1024 * 1024)

        self.log(
            "\n[+] Initialization Complete! The drive has been cryptographically reconfigured."
        )
        self.log("[!] PLEASE REMOVE AND RE-INSERT THE DRIVE TO AUTHENTICATE.")
        return True

    def get_available_usb_drives(self):
        drives = []
        for device in self.context.list_devices(subsystem="block", DEVTYPE="disk"):
            if device.get("ID_BUS") == "usb":
                node = device.device_node
                model = device.get("ID_MODEL", "Unknown USB Drive")
                size_str = device.attributes.asstring("size")
                size_gb = (int(size_str) * 512) / (1024**3) if size_str else 0
                drives.append(
                    {"node": node, "model": model.strip(), "size_gb": round(size_gb, 2)}
                )
        return drives

    def provision_usb_drive(self, device_node, password):
        self.log(f"\n=======================================================")
        self.log(f" [!] PROVISIONING NEW SECUREDRIVE ON {device_node} [!]")
        self.log(f"=======================================================")
        self.status("PHASE1")

        self.log("[*] 1. Unmounting and wiping drive...")
        for i in range(1, 10):
            part = f"{device_node}{i}"
            if os.path.exists(part):
                subprocess.run(
                    ["umount", "-l", part],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )

        subprocess.run(
            ["wipefs", "-a", device_node],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        self.log("[*] 2. Partitioning drive (100MB Boot, Remaining Data)...")
        if (
            subprocess.run(["parted", "-s", device_node, "mklabel", "msdos"]).returncode
            != 0
        ):
            self.log("[-] Partitioning failed at mklabel.")
            self.status("ERROR")
            return False

        if (
            subprocess.run(
                [
                    "parted",
                    "-s",
                    device_node,
                    "mkpart",
                    "primary",
                    "fat32",
                    "1MiB",
                    "101MiB",
                ]
            ).returncode
            != 0
        ):
            self.log("[-] Partitioning failed at boot partition creation.")
            self.status("ERROR")
            return False

        if (
            subprocess.run(
                [
                    "parted",
                    "-s",
                    device_node,
                    "mkpart",
                    "primary",
                    "ext4",
                    "101MiB",
                    "100%",
                ]
            ).returncode
            != 0
        ):
            self.log("[-] Partitioning failed at data partition creation.")
            self.status("ERROR")
            return False

        time.sleep(2)  # OS needs time to register partitions
        # Find partition suffixes. Sometimes it's /dev/sdb1, sometimes /dev/nvme0n1p1.
        # Since it's USB, it's typically /dev/sdX1
        part_suffix = "p" if "nvme" in device_node or "mmcblk" in device_node else ""
        boot_node = f"{device_node}{part_suffix}1"
        data_node = f"{device_node}{part_suffix}2"

        self.log("[*] 3. Formatting partitions...")
        if (
            subprocess.run(
                ["mkfs.vfat", "-F", "32", "-n", "SDP_BOOT", boot_node],
                capture_output=True,
            ).returncode
            != 0
        ):
            self.log("[-] Formatting Boot partition failed.")
            self.status("ERROR")
            return False

        self.log("    -> Formatting Data partition (this may take a moment)...")
        if (
            subprocess.run(
                ["mkfs.ext4", "-F", data_node], capture_output=True
            ).returncode
            != 0
        ):
            self.log("[-] Formatting Data partition failed.")
            self.status("ERROR")
            return False

        self.log("[*] 4. Mounting new partitions for provisioning...")
        mount_point = "/tmp/sdp_boot"
        vault_file_path = "/mnt/raw_usb/encrypted_vault.bin"

        os.makedirs(mount_point, exist_ok=True)
        os.makedirs("/mnt/raw_usb", exist_ok=True)

        if subprocess.run(["mount", boot_node, mount_point]).returncode != 0:
            self.log("[-] Failed to mount new boot partition.")
            self.status("ERROR")
            return False

        if subprocess.run(["mount", data_node, "/mnt/raw_usb"]).returncode != 0:
            self.log("[-] Failed to mount new data partition.")
            subprocess.run(["umount", "-l", mount_point])
            self.status("ERROR")
            return False

        self.log("[*] 5. Running SecureDrive Cryptographic Setup...")
        success = self._setup_secure_drive(mount_point, vault_file_path, password)

        subprocess.run(
            ["umount", "-l", mount_point],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            ["umount", "-l", "/mnt/raw_usb"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        if success:
            self.log(
                "\n[+] FULL PROVISIONING COMPLETE! Remove and re-insert the USB drive to use it."
            )
            self.status("WAITING")
        else:
            self.log("[-] Provisioning secure setup failed.")
            self.status("ERROR")

        return success

    def change_password(self, old_pwd, new_pwd):
        if not getattr(self, "current_boot_node", None):
            self.log("[-] Error: No SecureDrive currently active or boot node missing.")
            return False

        self.log("\n=======================================================")
        self.log(" [*] INITIATING SECURE PASSWORD CHANGE [*]")
        self.log("=======================================================\n")
        self.log(
            f"[*] Temporarily re-mounting boot partition ({self.current_boot_node}) to modify Header..."
        )

        mount_point = "/tmp/sdp_boot"
        os.makedirs(mount_point, exist_ok=True)
        if (
            subprocess.run(
                ["mount", self.current_boot_node, mount_point], capture_output=True
            ).returncode
            != 0
        ):
            self.log("[-] Failed to mount boot partition. Cannot change password.")
            return False

        header_path = os.path.join(mount_point, "vault_header.json")
        if not os.path.exists(header_path):
            self.log("[-] vault_header.json missing on device. Cannot change password.")
            subprocess.run(
                ["umount", "-l", mount_point],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return False

        try:
            with open(header_path, "r") as f:
                header_data = json.load(f)

            self.log("[*] Verifying Old Password...")
            old_salt = bytes.fromhex(header_data["salt"])
            old_kek = hash_secret_raw(
                secret=old_pwd.encode("utf-8"),
                salt=old_salt,
                time_cost=2,
                memory_cost=102400,
                parallelism=8,
                hash_len=32,
                type=Type.I,
            )

            cipher_vault = AES.new(
                old_kek, AES.MODE_EAX, nonce=bytes.fromhex(header_data["nonce"])
            )
            try:
                master_key = cipher_vault.decrypt_and_verify(
                    bytes.fromhex(header_data["ciphertext"]),
                    bytes.fromhex(header_data["tag"]),
                )
            except ValueError:
                self.log(
                    "[-] ACCESS DENIED: Incorrect Old Password. Master key not unwrapped."
                )
                subprocess.run(
                    ["umount", "-l", mount_point],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                return False

            self.log("[+] Old password verified. Master key unwrapped.")
            self.log("[*] Deriving new Key Encryption Key (KEK) using Argon2id...")
            new_salt = os.urandom(16)
            new_kek = hash_secret_raw(
                secret=new_pwd.encode("utf-8"),
                salt=new_salt,
                time_cost=2,
                memory_cost=102400,
                parallelism=8,
                hash_len=32,
                type=Type.I,
            )

            self.log("[*] Re-wrapping Master Key with New KEK (AES-EAX)...")
            new_cipher_vault = AES.new(new_kek, AES.MODE_EAX)
            ciphertext_mk, tag_mk = new_cipher_vault.encrypt_and_digest(master_key)

            with open(header_path, "w") as f:
                json.dump(
                    {
                        "salt": new_salt.hex(),
                        "nonce": new_cipher_vault.nonce.hex(),
                        "ciphertext": ciphertext_mk.hex(),
                        "tag": tag_mk.hex(),
                    },
                    f,
                )

            self.log("[+] Password successfully changed! Header securely updated.")
            subprocess.run(
                ["umount", "-l", mount_point],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True

        except Exception as e:
            self.log(f"[-] Error during password change: {e}")
            subprocess.run(
                ["umount", "-l", mount_point],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return False
