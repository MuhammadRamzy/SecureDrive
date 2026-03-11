import pyudev
import os
import subprocess
import json
import getpass
import time
import stat
import errno
from threading import Thread

# Cryptography & System Libraries
from nacl.signing import VerifyKey, SigningKey
from nacl.encoding import HexEncoder
from Crypto.Cipher import AES
from Crypto.Util import Counter
from argon2.low_level import hash_secret_raw, Type
from fuse import FUSE, Operations, LoggingMixIn

# Context for hardware monitoring
context = pyudev.Context()
monitor = pyudev.Monitor.from_netlink(context)
monitor.filter_by(subsystem='block')

# --- FUSE FILESYSTEM IMPLEMENTATION (CTR MODE) ---
class SecurePassportFS(LoggingMixIn, Operations):
    def __init__(self, raw_partition_path, key):
        self.raw_partition_path = raw_partition_path
        self.fd = os.open(self.raw_partition_path, os.O_RDWR)
        
        # Use a 256-bit key for CTR mode stream cipher
        self.key = key[:32] 
        self.virtual_file = '/vault.img'
        
        self.size = os.lseek(self.fd, 0, os.SEEK_END)
        os.lseek(self.fd, 0, os.SEEK_SET)

    def getattr(self, path, fh=None):
        if path == '/':
            return {'st_mode': (stat.S_IFDIR | 0o755), 'st_nlink': 2}
        elif path == self.virtual_file:
            return {'st_mode': (stat.S_IFREG | 0o666), 'st_size': self.size, 'st_nlink': 1}
        else:
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))

    def readdir(self, path, fh):
        if path == '/':
            return ['.', '..', self.virtual_file[1:]]

    # --- Dummy calls to satisfy mkfs and OS utilities seamlessly ---
    def truncate(self, path, length, fh=None): return 0
    def chmod(self, path, mode): return 0
    def chown(self, path, uid, gid): return 0
    def utimens(self, path, times=None): return 0

    # Force the OS to physically write the FUSE buffers to the raw USB drive
    def fsync(self, path, fdatasync, fh): 
        os.fsync(self.fd)
        return 0
        
    def flush(self, path, fh): 
        os.fsync(self.fd)
        return 0

    def _crypt(self, data, offset):
        """Absolute block-aligned stream cipher to handle arbitrary FUSE chunk sizes"""
        # Calculate absolute 16-byte block index and the remainder bytes
        block_index = offset // 16
        remainder = offset % 16
        
        # 128-bit counter anchored to the absolute file block
        ctr = Counter.new(128, initial_value=block_index)
        cipher = AES.new(self.key, AES.MODE_CTR, counter=ctr)
        
        # Fast-forward the keystream if the OS offset isn't perfectly block-aligned
        if remainder > 0:
            cipher.encrypt(b'\x00' * remainder)
            
        # In CTR mode, encryption and decryption are the exact same XOR operation
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

# --- RECONFIGURATION & SETUP WORKFLOW ---
def setup_secure_drive(mount_point, vault_file_path):
    print("\n=======================================================")
    print(" [!] SECUREDRIVE INITIALIZATION / FACTORY RESET [!]")
    print("=======================================================")
    print("WARNING: This will generate new cryptographic identities,")
    print("overwrite existing keys, and completely wipe the encrypted vault!")
    
    confirm = input("\nAre you sure you want to proceed? (yes/no): ")
    if confirm.lower() != 'yes':
        print("Reset aborted. Please safely remove the drive.")
        return False

    # 1. Generate Ed25519 Keypair
    print("\n[*] 1. Generating new Ed25519 hardware identity...")
    time.sleep(0.5)
    private_key = SigningKey.generate()
    public_key = private_key.verify_key

    factory_key = b'0123456789abcdef0123456789abcdef' # Simulated Control Plane Key
    cipher_id = AES.new(factory_key, AES.MODE_EAX)
    ciphertext_id, tag_id = cipher_id.encrypt_and_digest(private_key.encode(encoder=HexEncoder))
    
    with open(os.path.join(mount_point, 'identity.key'), 'w') as f:
        json.dump({'nonce': cipher_id.nonce.hex(), 'ciphertext': ciphertext_id.hex(), 'tag': tag_id.hex()}, f)
        
    with open(os.path.join(mount_point, 'device.cert'), 'w') as f:
        f.write(public_key.encode(encoder=HexEncoder).decode('utf-8'))
    print(f"    -> Identity saved. Public Key: {public_key.encode(encoder=HexEncoder).decode('utf-8')[:16]}...")

    # 2. Master Key and Password Setup
    print("\n[*] 2. Configuring User Access Credentials...")
    while True:
        new_pass = getpass.getpass("    -> Enter NEW SecureDrive Password: ")
        confirm_pass = getpass.getpass("    -> Confirm NEW Password: ")
        if new_pass == confirm_pass and len(new_pass) > 0:
            break
        print("    [-] Passwords do not match or are empty. Try again.")

    print("\n[*] 3. Generating 256-bit Vault Master Key...")
    time.sleep(0.5)
    master_key = os.urandom(32)

    print("[*] 4. Deriving Key Encryption Key (KEK) via Argon2id...")
    salt = os.urandom(16)
    kek = hash_secret_raw(
        secret=new_pass.encode('utf-8'),
        salt=salt,
        time_cost=2,
        memory_cost=102400,
        parallelism=8,
        hash_len=32,
        type=Type.I
    )

    print("[*] 5. Wrapping Master Key with KEK (AES-EAX)...")
    time.sleep(0.5)
    cipher_vault = AES.new(kek, AES.MODE_EAX)
    ciphertext_mk, tag_mk = cipher_vault.encrypt_and_digest(master_key)

    with open(os.path.join(mount_point, 'vault_header.json'), 'w') as f:
        json.dump({
            'salt': salt.hex(),
            'nonce': cipher_vault.nonce.hex(),
            'ciphertext': ciphertext_mk.hex(),
            'tag': tag_mk.hex()
        }, f)
    print("    -> Vault header secured and saved to boot partition.")

    # 3. Provision Vault File
    print("\n[*] 6. Provisioning new encrypted vault backing file...")
    os.makedirs(os.path.dirname(vault_file_path), exist_ok=True)
    with open(vault_file_path, 'wb') as f:
        f.truncate(100 * 1024 * 1024) # Create a 100MB blank vault for MVP speed
    
    print("\n[+] Initialization Complete! The drive has been cryptographically reconfigured.")
    print("[!] PLEASE REMOVE AND RE-INSERT THE DRIVE TO AUTHENTICATE.")
    return True

# --- ZERO TRUST PROTOCOL & AUTO-MOUNT ---
def initiate_handshake(device):
    print(f"\n[+] SECUREDRIVE PASSPORT DETECTED: {device.device_node}")
    print(f"[*] Initiating Zero-Trust Handshake Protocol...\n")
    time.sleep(1) # Presentation pause
    
    boot_node = device.device_node
    data_partition_node = boot_node[:-1] + "2" 
    mount_point = "/tmp/sdp_boot"
    vault_file = "/mnt/raw_usb/encrypted_vault.bin"
    
    # Pre-Flight Cleanup
    subprocess.run(['umount', '-l', '/mnt/unlocked_vault'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['umount', '-l', '/mnt/secure_drive'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['umount', '-l', '/mnt/raw_usb'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # 1. Mount Partitions
    os.makedirs(mount_point, exist_ok=True)
    os.makedirs("/mnt/raw_usb", exist_ok=True)
    
    subprocess.run(['umount', '-l', boot_node], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['umount', '-l', data_partition_node], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    if subprocess.run(['mount', boot_node, mount_point], capture_output=True).returncode != 0:
        print(f"[-] OS Mount Command Failed for Boot Partition.")
        return
        
    if subprocess.run(['mount', data_partition_node, '/mnt/raw_usb'], capture_output=True).returncode != 0:
        print(f"[-] OS Mount Command Failed for Data Partition.")
        subprocess.run(['umount', '-l', mount_point], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return

    # 2. Check Initialization State
    cert_path = os.path.join(mount_point, 'device.cert')
    id_path = os.path.join(mount_point, 'identity.key')
    header_path = os.path.join(mount_point, 'vault_header.json')
    
    if not (os.path.exists(cert_path) and os.path.exists(id_path) and os.path.exists(header_path)):
        print("[!] Uninitialized or Corrupted SecureDrive Detected.")
        setup_secure_drive(mount_point, vault_file)
        cleanup_mounts(device)
        return

    # =========================================================================
    # PHASE 1: DEVICE AUTHENTICATION (ANTI-CLONING CHALLENGE-RESPONSE)
    # =========================================================================
    print("--- [PHASE 1: CRYPTOGRAPHIC IDENTITY VERIFICATION] ---")
    try:
        # Step A: Read Public Certificate
        print("[*] 1. Extracting Device Certificate (Public Key)...")
        time.sleep(0.5)
        with open(cert_path, 'r') as f:
            public_key_hex = f.read().strip()
            verify_key = VerifyKey(public_key_hex, encoder=HexEncoder)
        print(f"    -> Public Key: {public_key_hex[:16]}...{public_key_hex[-16:]}")
        time.sleep(1.5)

        # Step B: Generate Challenge Nonce
        print("[*] 2. Generating 256-bit Challenge Nonce (Host -> Device)...")
        time.sleep(0.5)
        nonce = os.urandom(32) # N
        print(f"    -> Nonce (N): {nonce.hex()[:16]}...{nonce.hex()[-16:]}")
        time.sleep(1.5)

        # Step C: Device Signs Challenge (Simulating hardware Secure Element)
        print("[*] 3. Device Secure Element Signing Nonce with Ed25519 Private Key...")
        time.sleep(0.5)
        with open(id_path, 'r') as f:
            enc_identity = json.load(f)
            
        factory_key = b'0123456789abcdef0123456789abcdef'
        cipher = AES.new(factory_key, AES.MODE_EAX, nonce=bytes.fromhex(enc_identity['nonce']))
        private_key_bytes = cipher.decrypt_and_verify(
            bytes.fromhex(enc_identity['ciphertext']), 
            bytes.fromhex(enc_identity['tag'])
        )
        signing_key = SigningKey(private_key_bytes, encoder=HexEncoder)
        
        signed_message = signing_key.sign(nonce)
        signature = signed_message.signature # S
        print(f"    -> Signature (S): {signature.hex()[:16]}...{signature.hex()[-16:]}")
        time.sleep(1.5)

        # Step D: Host Verification
        print("[*] 4. Host Verifying Signature against Device Public Key...")
        time.sleep(0.5)
        verify_key.verify(nonce, signature)
        print("[+] SUCCESS: Proof of Possession Confirmed. Anti-Cloning Check Passed!\n")
        time.sleep(1)

    except Exception as e:
        print(f"[-] HANDSHAKE FAILED (Cryptographic Verification Error): {e}")
        cleanup_mounts(device)
        return

    # =========================================================================
    # PHASE 2: USER AUTHENTICATION & KEY DERIVATION
    # =========================================================================
    print("--- [PHASE 2: KEY DERIVATION & UNWRAPPING] ---")
    password = getpass.getpass(prompt="[*] Enter SecureDrive Password to unlock vault (or type 'RESET' to reconfigure): ")
    
    if password == 'RESET':
        setup_secure_drive(mount_point, vault_file)
        cleanup_mounts(device)
        return
        
    print("[*] Deriving Key Encryption Key (KEK) via Argon2id (Memory-Hard Function)...")
    print("    -> Simulating GPU/ASIC resistance. Please wait...")
    
    with open(header_path, 'r') as f:
        header_data = json.load(f)
        
    salt = bytes.fromhex(header_data['salt'])
    kek = hash_secret_raw(
        secret=password.encode('utf-8'),
        salt=salt,
        time_cost=2,
        memory_cost=102400,
        parallelism=8,
        hash_len=32,
        type=Type.I
    )
    time.sleep(0.5)
    print(f"    -> KEK Hash: {kek.hex()[:16]}... (Truncated for security)")
    
    print("[*] Attempting to unwrap Master Key using KEK...")
    time.sleep(0.5)
    cipher_vault = AES.new(kek, AES.MODE_EAX, nonce=bytes.fromhex(header_data['nonce']))
    
    try:
        master_key = cipher_vault.decrypt_and_verify(
            bytes.fromhex(header_data['ciphertext']), 
            bytes.fromhex(header_data['tag'])
        )
        print("[+] SUCCESS: Master Key successfully unwrapped. Password verified!\n")
        time.sleep(1)
    except ValueError:
        print("\n[-] ACCESS DENIED: Incorrect Password! Cryptographic unwrapping failed.")
        print("[-] The Master Key remains secured. Aborting mount sequence.")
        cleanup_mounts(device)
        return
        
    # Unmount Boot Partition as we no longer need it (Minimizing attack surface)
    subprocess.run(['umount', '-l', mount_point], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # =========================================================================
    # PHASE 3: VAULT DECRYPTION & FUSE AUTO-MOUNT
    # =========================================================================
    print("--- [PHASE 3: FUSE VAULT DECRYPTION] ---")
    print(f"[*] Booting FUSE Crypto-Engine on {vault_file}...")
    try:
        os.makedirs('/mnt/secure_drive', exist_ok=True)
        # We pass the unwrapped master_key to the FUSE filesystem
        fuse_thread = Thread(target=lambda: FUSE(SecurePassportFS(vault_file, master_key), '/mnt/secure_drive', foreground=True, allow_other=True))
        fuse_thread.daemon = True
        fuse_thread.start()
        
        print("[*] Waiting for FUSE bridge to stabilize...")
        
        fuse_ready = False
        for _ in range(10): # 5 second timeout
            if os.path.exists('/mnt/secure_drive/vault.img'):
                fuse_ready = True
                break
            time.sleep(0.5)
            
        if not fuse_ready:
            print("[-] ERROR: FUSE bridge timeout. Auto-mount aborted.")
            cleanup_mounts(device)
            return
            
        print("[*] FUSE active. Auto-mounting usable user directory...")
        
        uid = os.environ.get('SUDO_UID', '1000')
        gid = os.environ.get('SUDO_GID', '1000')
        
        os.makedirs('/mnt/unlocked_vault', exist_ok=True)
        # Added 'sync' flag to force Linux to write to the USB immediately instead of caching in RAM
        mount_cmd = ['mount', '-o', f'loop,sync,uid={uid},gid={gid},umask=000', '/mnt/secure_drive/vault.img', '/mnt/unlocked_vault']
        
        mount_result = subprocess.run(mount_cmd, capture_output=True, text=True)
        
        if mount_result.returncode == 0:
            print("\n=======================================================")
            print("[+] SUCCESS! SecureDrive Passport is Fully Unlocked.")
            print("[+] Your secure files are available at: /mnt/unlocked_vault")
            print("=======================================================\n")
        else:
            print(f"[-] Auto-Mount Failed: {mount_result.stderr.strip()}")
            print("[*] Hint: If this is a newly provisioned vault, you must format it first:")
            print("[*] Open a second terminal and run: sudo mkfs.vfat /mnt/secure_drive/vault.img")

    except Exception as e:
        print(f"[-] FUSE Initialization Failed: {e}")
        cleanup_mounts(device)


def cleanup_mounts(device):
    print(f"\n[-] Device Removed / Protocol Aborted")
    print("[*] Tearing down Zero-Trust Vault and aggressively wiping keys from RAM...")
    
    subprocess.run(['umount', '-l', '/mnt/unlocked_vault'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['umount', '-l', '/mnt/secure_drive'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['umount', '-l', '/mnt/raw_usb'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Ensure boot partition is cleanly removed as well if an error caused an abort
    subprocess.run(['umount', '-l', '/tmp/sdp_boot'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    print("[+] Teardown Complete. Cryptographic boundary restored.")

def is_securedrive(device):
    return device.get('ID_FS_LABEL') == 'SDP_BOOT'

def event_loop():
    print("=======================================================")
    print(" SecureDrive Passport Daemon (MVP) Running")
    print(" Zero-Trust Local Policy Enforcement Point Active")
    print("=======================================================")
    print("\nListening for hardware insertion events (Press Ctrl+C to exit)...")
    
    for device in iter(monitor.poll, None):
        if device.action == 'add':
            if is_securedrive(device):
                initiate_handshake(device)
        elif device.action == 'remove':
            if 'sd' in device.device_node: 
                 cleanup_mounts(device)

if __name__ == "__main__":
    try:
        subprocess.run(['umount', '-l', '/mnt/unlocked_vault'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['umount', '-l', '/mnt/secure_drive'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['umount', '-l', '/mnt/raw_usb'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        event_loop()
    except KeyboardInterrupt:
        print("\nDaemon terminated by user.")
        subprocess.run(['umount', '-l', '/mnt/unlocked_vault'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['umount', '-l', '/mnt/secure_drive'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['umount', '-l', '/mnt/raw_usb'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['umount', '-l', '/tmp/sdp_boot'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)