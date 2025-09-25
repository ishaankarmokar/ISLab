# ==============================================================================
#           >> INFORMATION SECURITY LAB - PYTHON CHEAT SHEET <<
#
# Instructions:
# 1. Scroll to the section you need.
# 2. Copy the function or class you require.
# 3. Use the "ULTIMATE EXAM TEMPLATE" (Section 4) as your main starting point.
# 4. Fill in the template with functions from the other sections.
# 5. Check Section 6 for usage examples of complex functions.
#
# ==============================================================================

# ==============================================================================
# 0. ALL IMPORTS
# ==============================================================================
import os
import time
import hashlib
import random
import socket
import threading
from datetime import datetime

# --- PyCryptodome Library ---
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import AES, DES, DES3, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes, GCD
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256, SHA512

from cryptography.hazmat.primitives.asymmetric import rsa as rsa_hazmat
from cryptography.hazmat.primitives.asymmetric import ec as ec_hazmat
from cryptography.hazmat.primitives.asymmetric import padding as padding_hazmat
from cryptography.hazmat.primitives import hashes as hashes_hazmat


    
def aes_encrypt(key, plaintext_bytes, mode=AES.MODE_CBC):
    """Encrypts with AES. Returns iv + ciphertext for CBC, or just ciphertext for ECB."""
    if mode == AES.MODE_CBC:
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(plaintext_bytes, AES.block_size))
        return cipher.iv + ct_bytes
    elif mode == AES.MODE_ECB:
        cipher = AES.new(key, AES.MODE_ECB)
        ct_bytes = cipher.encrypt(pad(plaintext_bytes, AES.block_size))
        return ct_bytes
    else:
        raise ValueError("Unsupported AES mode")

def aes_decrypt(key, ciphertext_bytes, mode=AES.MODE_CBC):
    """Decrypts with AES."""
    if mode == AES.MODE_CBC:
        iv = ciphertext_bytes[:16]
        ct = ciphertext_bytes[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), AES.block_size)
    elif mode == AES.MODE_ECB:
        cipher = AES.new(key, AES.MODE_ECB)
        return unpad(cipher.decrypt(ciphertext_bytes), AES.block_size)
    else:
        raise ValueError("Unsupported AES mode")

# --- Asymmetric Ciphers (RSA) ---
def generate_rsa_keys(bits=2048):
    """Returns a new RSA key pair object."""
    return RSA.generate(bits)

def rsa_encrypt(public_key, plaintext_bytes):
    """Encrypts bytes using an RSA public key."""
    cipher_rsa = PKCS1_OAEP.new(public_key)
    return cipher_rsa.encrypt(plaintext_bytes)

def rsa_decrypt(private_key, ciphertext_bytes):
    """Decrypts bytes using an RSA private key."""
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(ciphertext_bytes)
    
# --- Digital Signatures (RSA-PSS via cryptography.hazmat) ---
def generate_rsa_hazmat_keys(bits=2048):
    """Generates RSA keys for signing using cryptography.hazmat."""
    private_key = rsa_hazmat.generate_private_key(
        public_exponent=65537,
        key_size=bits
    )
    return private_key, private_key.public_key()

def sign_rsa_pss(private_key, message_hash):
    """Signs a HASH using an RSA private key with PSS padding."""
    return private_key.sign(
        message_hash,
        padding_hazmat.PSS(
            mgf=padding_hazmat.MGF1(hashes_hazmat.SHA256()),
            salt_length=padding_hazmat.PSS.MAX_LENGTH
        ),
        hashes_hazmat.SHA256() # Algorithm must match hash used for data
    )

def verify_rsa_pss(public_key, message_hash, signature):
    """Verifies an RSA-PSS signature on a HASH."""
    try:
        public_key.verify(
            signature,
            message_hash,
            padding_hazmat.PSS(
                mgf=padding_hazmat.MGF1(hashes_hazmat.SHA256()),
                salt_length=padding_hazmat.PSS.MAX_LENGTH
            ),
            hashes_hazmat.SHA256()
        )
        return True
    except Exception:
        return False


def get_hash(data_bytes, algorithm='sha512'):
    """Computes the hash of bytes using a specified algorithm."""
    hasher = hashlib.new(algorithm)
    hasher.update(data_bytes)
    return hasher.digest() # .digest() for bytes, .hexdigest() for string

def get_timestamp():
    """Returns a formatted timestamp string."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# ==============================================================================
# 4. THE ULTIMATE EXAM TEMPLATE (Role-Based System)
# ==============================================================================

class MediSecure:
    """
    A flexible, plug-and-play class structure for a role-based crypto system.
    Customize the _setup_users() and menu functions for your specific question.
    """
    def __init__(self):
        # In-memory storage for users, keys, and records
        self.users = {
            "patient": {"keys": {}},
            "doctor": {"keys": {}},
            "auditor": {}
        }
        self.pending_transactions = []
        self.processed_transactions = []
        
        print(f"[{get_timestamp()}] System Initialized. Setting up users...")
        self._setup_users()

    def _setup_users(self):
        print("Generating AES shared key...")
        self.shared_aes_key = get_random_bytes(32) # AES-256
        print("Generating RSA signing keys for Patient...")
        rsa_priv, rsa_pub = generate_rsa_hazmat_keys()
        self.users["patient"]["keys"]["rsa_priv"] = rsa_priv
        self.users["patient"]["keys"]["rsa_pub"] = rsa_pub
        
        print(f"[{get_timestamp()}] User setup complete.")

    def patient_menu(self):
        print("\n--- Patient Menu ---")
        plaintext = input("Enter medical details (e.g., 'Blood pressure levels'): ")
        
        # 1. Encrypt the details with AES
        ciphertext = aes_encrypt(self.shared_aes_key, plaintext.encode('utf-8'))
        print(f"  - Encrypted details with AES.")
        
        # 2. HASH the ciphertext
        original_hash = get_hash(ciphertext, 'sha512')
        print(f"  - Generated SHA-512 hash: {original_hash.hex()}")

        # 3. SIGN the hash
        patient_priv_key = self.users["patient"]["keys"]["rsa_priv"]
        patient_pub_key = self.users["patient"]["keys"]["rsa_pub"]
        signature = sign_rsa_pss(patient_priv_key, original_hash)
        print(f"  - Signed hash with RSA-PSS.")
        
        # 4. Store the bundle
        transaction = {
            "timestamp": get_timestamp(),
            "ciphertext": ciphertext,
            "original_hash": original_hash,
            "signature": signature,
            "status": "pending"
        }
        self.pending_transactions.append(transaction)
        print(f"[{get_timestamp()}] Transaction sent successfully.")

    def doctor_menu(self):
        print("\n--- Doctor Menu ---")
        if not self.pending_transactions:
            print("No pending transactions to process.")
            return

        # Process the first pending transaction
        transaction = self.pending_transactions.pop(0)
        print(f"Processing transaction from {transaction['timestamp']}...")
        
        # 1. Hash the ciphertext
        computed_hash = get_hash(transaction["ciphertext"], 'sha512')
        print(f"  - Computed SHA-512 hash on received ciphertext.")

        # 2. VERIFY integrity

        integrity_ok = (computed_hash == transaction["original_hash"])
        print(f"  - Integrity Check (hashes match): {integrity_ok}")

        # 3. VERIFY authenticity
        patient_pub_key = self.users["patient"]["keys"]["rsa_pub"]
        authenticity_ok = verify_rsa_pss(patient_pub_key, transaction["original_hash"], transaction["signature"])
        print(f"  - Authenticity Check (signature valid): {authenticity_ok}")

        # 4. decrypt the ciphertext
        decrypted_plaintext = aes_decrypt(self.shared_aes_key, transaction["ciphertext"])
        print(f"  - Decrypted details: {decrypted_plaintext.decode('utf-8')}")


        # 5. Record results
        if integrity_ok and authenticity_ok:
            transaction['status'] = 'processed_successfully'
            print(f"[{get_timestamp()}] Transaction Verified and Processed.")
        else:
            transaction['status'] = 'failed_verification'
            print(f"[{get_timestamp()}] TRANSACTION FAILED VERIFICATION.")
        
        transaction['computed_hash'] = computed_hash
        self.processed_transactions.append(transaction)

    def auditor_menu(self):
        print("\n--- Auditor Menu ---")
        if not self.processed_transactions:
            print("No processed transactions to audit.")
            return

        for i, tx in enumerate(self.processed_transactions):
            print(f"\nAuditing Transaction {i+1} (Status: {tx['status']})")
            
            # 1. View hashes for integrity check
            print(f"  - Stored Hash:    {tx['original_hash'].hex()}")
            if 'computed_hash' in tx:
                print(f"  - Computed Hash:  {tx['computed_hash'].hex()}")
                print(f"  - Integrity Match: {tx['original_hash'] == tx['computed_hash']}")

            # 2. Independently VERIFY the signature
            patient_pub_key = self.users["patient"]["keys"]["rsa_pub"]
            signature_valid = verify_rsa_pss(patient_pub_key,tx["original_hash"], tx["signature"])
            print(f"  - Signature Verification: {'VALID' if signature_valid else 'INVALID'}")

    def main_loop(self):
        while True:
            print("\n===================================")
            print("  Secure System Main Menu")
            print("===================================")
            print("1. Act as Patient")
            print("2. Act as Doctor")
            print("3. Act as Auditor")
            print("4. Exit")
            choice = input("Enter your choice: ")

            if choice == '1':
                self.patient_menu()
            elif choice == '2':
                self.doctor_menu()
            elif choice == '3':
                self.auditor_menu()
            elif choice == '4':
                print("Exiting system.")
                break
            else:
                print("Invalid choice, please try again.")


if __name__ == "__main__":

    
    system = MediSecure()
    system.main_loop()