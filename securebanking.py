# 0. ALL IMPORTS
# ==============================================================================
import os
import time
import hashlib
import random
import socket
import threading
from datetime import datetime

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

def generate_rabin_keys(bits=1024):
    """Generates keys for the Rabin cryptosystem."""
    # Find p and q such that p ≡ 3 (mod 4) and q ≡ 3 (mod 4)
    p = getPrime(bits // 2)
    while p % 4 != 3:
        p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    while q % 4 != 3 or p == q:
        q = getPrime(bits // 2)

    n = p * q
    return (n,), (p, q) # (public_key,), (private_key,)

def rabin_encrypt(public_key, plaintext_str):
    """Encrypts a string using the Rabin public key."""
    n, = public_key
    # Pad plaintext to be a square, can be improved but simple padding is fine
    plaintext_bytes = plaintext_str.encode('utf-8')
    m = bytes_to_long(plaintext_bytes)
    if m >= n:
        raise ValueError("Message is too large for the key size.")
    return pow(m, 2, n)

def rabin_decrypt(private_key, ciphertext):
    """
    Decrypts Rabin ciphertext. Returns a list of 4 possible plaintext roots.
    The receiver must determine which root is the correct original message.
    """
    p, q = private_key
    n = p * q
    
    # 1. Find square roots modulo p and q
    mp = pow(ciphertext, (p + 1) // 4, p)
    mq = pow(ciphertext, (q + 1) // 4, q)
    
    # 2. Use Extended Euclidean Algorithm to find yp and yq
    # such that (yp * p) + (yq * q) = 1
    _, yp, yq = egcd(p, q)

    # 3. Use Chinese Remainder Theorem to find the 4 roots
    r1 = (yp * p * mq + yq * q * mp) % n
    r2 = n - r1
    r3 = (yp * p * mq - yq * q * mp) % n
    r4 = n - r3
    
    roots_as_bytes = []
    for r in [r1, r2, r3, r4]:
        try:
            roots_as_bytes.append(long_to_bytes(r))
        except Exception:
            roots_as_bytes.append(b'(decoding error)')
            
    return roots_as_bytes

def egcd(a, b):
    """Helper for CRT in Rabin decryption."""
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def generate_elgamal_keys(bits=512):
    """Generates keys for the ElGamal Signature Scheme."""
    p = getPrime(bits)
    g = random.randint(2, p - 2)
    x = random.randint(1, p - 2)  # Private key
    y = pow(g, x, p)             # Public key component
    return (p, g, y), x          # public_key, private_key

def sign_elgamal(message_hash, private_key, public_key):
    """Signs a message HASH using the ElGamal private key."""
    p, g, y = public_key
    x = private_key
    m = bytes_to_long(message_hash)
    
    while True:
        k = random.randint(1, p - 2)
        if GCD(k, p - 1) == 1:
            break
            
    r = pow(g, k, p)
    k_inv = inverse(k, p - 1)
    s = (k_inv * (m - x * r)) % (p - 1)
    
    return (r, s)

def verify_elgamal(message_hash, signature, public_key):
    """Verifies an ElGamal signature on a message HASH."""
    p, g, y = public_key
    r, s = signature
    m = bytes_to_long(message_hash)

    if not (0 < r < p and 0 < s < p - 1):
        return False
        
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, m, p)
    
    return v1 == v2


def get_hash(data_bytes, algorithm='sha512'):
    """Computes the hash of bytes using a specified algorithm."""
    hasher = hashlib.new(algorithm)
    hasher.update(data_bytes)
    return hasher.digest() # .digest() for bytes, .hexdigest() for string

def get_timestamp():
    """Returns a formatted timestamp string."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class SecureSystemTemplate:
    """
    A flexible, plug-and-play class structure for a role-based crypto system.
    Customize the _setup_users() and menu functions for your specific question.
    """
    def __init__(self):
        # In-memory storage for users, keys, and records
        self.users = {
            "customer": {"keys": {}},
            "merchant": {"keys": {}},
            "auditor": {}
        }
        self.pending_transactions = []
        self.processed_transactions = []
        
        print(f"[{get_timestamp()}] System Initialized. Setting up users...")
        self._setup_users()

    def _setup_users(self):
        
        print("Generating ElGamal keys for Customer...")
        elgamal_pub, elgamal_priv = generate_elgamal_keys()
        self.users["customer"]["keys"]["elgamal_pub"] = elgamal_pub
        self.users["customer"]["keys"]["elgamal_priv"] = elgamal_priv
        
        print("Generating Rabin keys for Merchant...")
        rabin_pub, rabin_priv = generate_rabin_keys()
        self.users["merchant"]["keys"]["rabin_pub"] = rabin_pub
        self.users["merchant"]["keys"]["rabin_priv"] = rabin_priv
        
        print(f"[{get_timestamp()}] User setup complete.")

    def customer_menu(self):
        print("\n--- Customer Menu ---")
        plaintext = input("Enter transaction details (e.g., 'Send 500 to Bob'): ")
        
        
        # 1. HASH the plaintext
        original_hash = get_hash(plaintext.encode('utf-8'), 'sha512')
        print(f"  - Generated SHA-512 hash: {original_hash.hex()}")

        # 2. SIGN the hash
        customer_priv_key = self.users["customer"]["keys"]["elgamal_priv"]
        customer_pub_key = self.users["customer"]["keys"]["elgamal_pub"]
        signature = sign_elgamal(original_hash, customer_priv_key, customer_pub_key)
        print(f"  - Signed hash with ElGamal.")

        # 3. ENCRYPT the plaintext
        merchant_pub_key = self.users["merchant"]["keys"]["rabin_pub"]
        ciphertext = rabin_encrypt(merchant_pub_key, plaintext)
        print(f"  - Encrypted details with Rabin.")
        
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

    def merchant_menu(self):
        print("\n--- Merchant Menu ---")
        if not self.pending_transactions:
            print("No pending transactions to process.")
            return

        # Process the first pending transaction
        transaction = self.pending_transactions.pop(0)
        print(f"Processing transaction from {transaction['timestamp']}...")
        
        # 1. DECRYPT the ciphertext
        merchant_priv_key = self.users["merchant"]["keys"]["rabin_priv"]
        possible_plaintexts = rabin_decrypt(merchant_priv_key, transaction["ciphertext"])
        
        # Find the correct plaintext (must be a valid UTF-8 string)
        decrypted_plaintext = b''
        for pt_bytes in possible_plaintexts:
            try:
                pt_bytes.decode('utf-8')
                decrypted_plaintext = pt_bytes # Found it
                break
            except UnicodeDecodeError:
                continue # This wasn't the right root
        
        if not decrypted_plaintext:
            print("  - DECRYPTION FAILED: No valid plaintext found.")
            transaction['status'] = 'failed_decryption'
            self.processed_transactions.append(transaction)
            return

        print(f"  - Decrypted Plaintext: '{decrypted_plaintext.decode()}'")

        # 2. HASH the now-decrypted plaintext
        computed_hash = get_hash(decrypted_plaintext, 'sha512')
        print(f"  - Computed SHA-512 hash on decrypted data.")

        # 3. VERIFY integrity
        integrity_ok = (computed_hash == transaction["original_hash"])
        print(f"  - Integrity Check (hashes match): {integrity_ok}")

        # 4. VERIFY authenticity
        customer_pub_key = self.users["customer"]["keys"]["elgamal_pub"]
        authenticity_ok = verify_elgamal(transaction["original_hash"], transaction["signature"], customer_pub_key)
        print(f"  - Authenticity Check (signature valid): {authenticity_ok}")

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
            customer_pub_key = self.users["customer"]["keys"]["elgamal_pub"]
            signature_valid = verify_elgamal(tx["original_hash"], tx["signature"], customer_pub_key)
            print(f"  - Signature Verification: {'VALID' if signature_valid else 'INVALID'}")

    def main_loop(self):
        """A simple, robust menu to switch between roles."""
        while True:
            print("\n===================================")
            print("  Secure System Main Menu")
            print("===================================")
            print("1. Act as Customer")
            print("2. Act as Merchant")
            print("3. Act as Auditor")
            print("4. Exit")
            choice = input("Enter your choice: ")

            if choice == '1':
                self.customer_menu()
            elif choice == '2':
                self.merchant_menu()
            elif choice == '3':
                self.auditor_menu()
            elif choice == '4':
                print("Exiting system.")
                break
            else:
                print("Invalid choice, please try again.")


if __name__ == "__main__":
    
    system = SecureSystemTemplate()
    system.main_loop()
