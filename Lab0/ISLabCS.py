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

# --- Cryptography.hazmat Library ---
# Note: Use one library consistently if possible to avoid conflicts.
# Included here for completeness.
from cryptography.hazmat.primitives.asymmetric import rsa as rsa_hazmat
from cryptography.hazmat.primitives.asymmetric import ec as ec_hazmat
from cryptography.hazmat.primitives.asymmetric import padding as padding_hazmat
from cryptography.hazmat.primitives import hashes as hashes_hazmat


# ==============================================================================
# 1. MANUAL IMPLEMENTATIONS (For specific required algorithms)
# ==============================================================================

def vigenere_cipher(message, key, mode='encrypt'):
    """
    Encrypts or decrypts using the Vigenère cipher.
    mode: 'encrypt' or 'decrypt'
    """
    message = "".join(filter(str.isalpha, message)).lower()
    key = "".join(filter(str.isalpha, key)).lower()
    result = ""
    key_idx = 0

    for char in message:
        key_char = key[key_idx % len(key)]
        key_offset = ord(key_char) - ord('a')
        char_offset = ord(char) - ord('a')

        if mode == 'encrypt':
            new_char_code = (char_offset + key_offset) % 26
        elif mode == 'decrypt':
            new_char_code = (char_offset - key_offset + 26) % 26
        else:
            raise ValueError("Mode must be 'encrypt' or 'decrypt'")

        result += chr(new_char_code + ord('a'))
        key_idx += 1

    return result.upper()

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

def classical_diffie_hellman_exchange():
    """Simulates a classical Diffie-Hellman key exchange and returns the shared key."""
    # 1. Agree on public parameters (p: prime, g: generator)
    p = getPrime(512)
    g = 2

    # 2. Alice generates her keys
    alice_private = random.randint(2, p - 2)
    alice_public = pow(g, alice_private, p)

    # 3. Bob generates his keys
    bob_private = random.randint(2, p - 2)
    bob_public = pow(g, bob_private, p)

    # 4. They exchange public keys and compute the shared secret
    alice_shared_secret = pow(bob_public, alice_private, p)
    bob_shared_secret = pow(alice_public, bob_private, p)
    
    assert alice_shared_secret == bob_shared_secret
    
    # 5. Derive a symmetric key from the shared secret using a hash function
    shared_key = get_hash(long_to_bytes(alice_shared_secret), 'sha256')
    
    return shared_key

# ==============================================================================
# 2. HIGH-LEVEL BUILDING BLOCKS (Library Functions)
# ==============================================================================

# --- Symmetric Ciphers ---
def des_encrypt(key_bytes, plaintext_bytes): # 8-byte key
    cipher = DES.new(key_bytes, DES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext_bytes, DES.block_size))
    return cipher.iv + ct_bytes

def des_decrypt(key_bytes, ciphertext_bytes): # 8-byte key
    iv = ciphertext_bytes[:8]
    ct = ciphertext_bytes[8:]
    cipher = DES.new(key_bytes, DES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), DES.block_size)

def des3_encrypt(key_bytes, plaintext_bytes): # 16 or 24-byte key
    cipher = DES3.new(key_bytes, DES3.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext_bytes, DES3.block_size))
    return cipher.iv + ct_bytes

def des3_decrypt(key_bytes, ciphertext_bytes): # 16 or 24-byte key
    iv = ciphertext_bytes[:8]
    ct = ciphertext_bytes[8:]
    cipher = DES3.new(key_bytes, DES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), DES3.block_size)
    
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

# --- ECC Hybrid Encryption (ECIES) ---
def ecc_hybrid_encrypt(receiver_public_key, message_bytes):
    # Use ephemeral key for perfect forward secrecy
    ephemeral_key = ECC.generate(curve='P-256')
    
    # Derive shared secret (ECDH) and then a symmetric key (HKDF)
    shared_secret_point = ephemeral_key.d * receiver_public_key.pointQ
    shared_secret_bytes = int(shared_secret_point.x).to_bytes(32, 'big')
    derived_key = HKDF(shared_secret_bytes, 32, b'salt', SHA256)

    # Encrypt the message with AES-GCM using the derived key
    cipher_aes = AES.new(derived_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message_bytes)
    
    # Return all the parts the receiver needs to decrypt
    return {
        "ephemeral_pub_key": ephemeral_key.public_key(),
        "nonce": cipher_aes.nonce,
        "ciphertext": ciphertext,
        "tag": tag
    }

def ecc_hybrid_decrypt(receiver_private_key, encrypted_bundle):
    eph_pub_key = encrypted_bundle["ephemeral_pub_key"]
    nonce = encrypted_bundle["nonce"]
    ciphertext = encrypted_bundle["ciphertext"]
    tag = encrypted_bundle["tag"]

    # Re-derive the same shared secret and symmetric key
    shared_secret_point = receiver_private_key.d * eph_pub_key.pointQ
    shared_secret_bytes = int(shared_secret_point.x).to_bytes(32, 'big')
    derived_key = HKDF(shared_secret_bytes, 32, b'salt', SHA256)

    # Decrypt and verify the message
    cipher_aes = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
    return cipher_aes.decrypt_and_verify(ciphertext, tag)
        
# ==============================================================================
# 3. UTILITY FUNCTIONS
# ==============================================================================

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
        # --- TODO: CUSTOMIZE KEY GENERATION FOR YOUR QUESTION ---
        
        # Example for Q1 (Rabin + ElGamal):
        print("Generating ElGamal keys for Customer...")
        elgamal_pub, elgamal_priv = generate_elgamal_keys()
        self.users["customer"]["keys"]["elgamal_pub"] = elgamal_pub
        self.users["customer"]["keys"]["elgamal_priv"] = elgamal_priv
        
        print("Generating Rabin keys for Merchant...")
        rabin_pub, rabin_priv = generate_rabin_keys()
        self.users["merchant"]["keys"]["rabin_pub"] = rabin_pub
        self.users["merchant"]["keys"]["rabin_priv"] = rabin_priv
        
        # Example for Q2 (AES + RSA Signature):
        # print("Generating AES shared key...")
        # self.shared_aes_key = get_random_bytes(32) # AES-256
        # print("Generating RSA signing keys for Patient...")
        # rsa_priv, rsa_pub = generate_rsa_hazmat_keys()
        # self.users["patient"]["keys"]["rsa_priv"] = rsa_priv
        # self.users["patient"]["keys"]["rsa_pub"] = rsa_pub
        
        print(f"[{get_timestamp()}] User setup complete.")

    def customer_menu(self):
        print("\n--- Customer Menu ---")
        plaintext = input("Enter transaction details (e.g., 'Send 500 to Bob'): ")
        
        # --- TODO: CUSTOMIZE CUSTOMER ACTIONS ---
        
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

        # --- TODO: CUSTOMIZE MERCHANT ACTIONS ---
        
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
            
            # --- TODO: CUSTOMIZE AUDITOR ACTIONS ---
            
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

# ==============================================================================
# 5. EXAMPLE USAGE SNIPPETS
# ==============================================================================

def run_usage_examples():
    print("\n--- Running Usage Examples ---")
    
    # --- Classical Diffie-Hellman Example ---
    # print("\n1. Classical Diffie-Hellman Key Exchange:")
    # shared_key_dh = classical_diffie_hellman_exchange()
    # print(f"  - A shared AES key was derived: {shared_key_dh.hex()}")
    # message_to_encrypt = b"This message is secured by a DH key."
    # encrypted = aes_encrypt(shared_key_dh, message_to_encrypt)
    # decrypted = aes_decrypt(shared_key_dh, encrypted)
    # assert message_to_encrypt == decrypted
    # print("  - Successfully used the key for AES encryption/decryption.")
    
    # --- ECC Hybrid Encryption (ECIES) Example ---
    # print("\n2. ECC Hybrid Encryption (ECIES):")
    # # Generate a long-term key pair for the receiver (e.g., Bob)
    # bob_private_key = ECC.generate(curve='P-256')
    # bob_public_key = bob_private_key.public_key()
    # print("  - Bob generated his long-term ECC key pair.")
    
    # # The sender (e.g., Alice) encrypts a message using Bob's public key
    # message = b"This is a top secret message for Bob."
    # encrypted_bundle = ecc_hybrid_encrypt(bob_public_key, message)
    # print("  - Alice encrypted a message for Bob.")
    
    # # Bob receives the bundle and decrypts it with his private key
    # decrypted_message = ecc_hybrid_decrypt(bob_private_key, encrypted_bundle)
    # print(f"  - Bob decrypted the message: '{decrypted_message.decode()}'")
    # assert message == decrypted_message
    # print("  - Verification successful.")
    
    print("\n--- End of Examples ---")

# ==============================================================================
# 6. MAIN EXECUTION BLOCK
# ==============================================================================
if __name__ == "__main__":
    # To run the system for your exam, just instantiate and run the main_loop.
    # Make sure you have customized the template above first!
    
    # run_usage_examples() # Uncomment to see examples in action
    
    system = SecureSystemTemplate()
    system.main_loop()