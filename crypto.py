import os
import base64
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from config import settings

# Initialize Argon2id (Resistant to GPU cracking and side-channel attacks)
ph = PasswordHasher(
    time_cost=3,         # Protects against brute-force
    memory_cost=65536,   # 64MB - Protects against ASIC/FPGA
    parallelism=4,       # Threads
    hash_len=32,
    salt_len=16
)

class CryptoManager:
    """
    Handles symmetrical encryption for sensitive data (PII, Refresh Tokens)
    using AES-256-GCM.
    """
    
    def __init__(self):
        try:
            self.key = base64.urlsafe_b64decode(settings.DATA_ENCRYPTION_KEY)
            if len(self.key) != 32:
                raise ValueError("Key must be 32 bytes (256 bits) for AES-256")
        except Exception as e:
            raise ValueError(f"Invalid Encryption Key configuration: {e}")

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypts data using AES-GCM.
        IV is generated randomly for every operation.
        Returns: iv_hex:ciphertext_hex:tag_hex
        """
        iv = os.urandom(12)  # NIST recommended IV length for GCM
        encryptor = Cipher(
            algorithms.AES(self.key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()
        
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        
        # Format: IV:Ciphertext:AuthTag
        return f"{iv.hex()}:{ciphertext.hex()}:{encryptor.tag.hex()}"

    def decrypt(self, encrypted_payload: str) -> str:
        """
        Decrypts AES-GCM payload.
        Verifies authentication tag to prevent tampering.
        """
        try:
            iv_hex, ct_hex, tag_hex = encrypted_payload.split(':')
            iv = bytes.fromhex(iv_hex)
            ciphertext = bytes.fromhex(ct_hex)
            tag = bytes.fromhex(tag_hex)
            
            decryptor = Cipher(
                algorithms.AES(self.key),
                modes.GCM(iv, tag),
                backend=default_backend()
            ).decryptor()
            
            return (decryptor.update(ciphertext) + decryptor.finalize()).decode()
        except Exception:
            # Return generic error to prevent padding oracle leakage (though GCM handles this)
            raise ValueError("Decryption failed or data tampered")

    @staticmethod
    def hash_password(password: str) -> str:
        return ph.hash(password)

    @staticmethod
    def verify_password(hash: str, password: str) -> bool:
        try:
            return ph.verify(hash, password)
        except VerifyMismatchError:
            return False
        except Exception:
            return False

crypto_manager = CryptoManager()