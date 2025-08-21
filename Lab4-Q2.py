import os
import json
import logging
import threading
import time
from datetime import datetime, timedelta, timezone

from Crypto.Util import number
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# === CONFIG ===
KEY_SIZE = 1024  # bits, configurable
KEY_RENEWAL_DAYS = 365
STORAGE_DIR = 'keys_storage'
MASTER_KEY = b'secure_master_key_32byteslong!!!!!!!'  # 32 bytes for AES-256

# === LOGGING ===
logging.basicConfig(
    filename='key_management.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# === IN-MEMORY DB SIMULATION ===
hospital_db = {}


# === UTILS ===

def pad(data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)


def unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if not 1 <= pad_len <= 16:
        raise ValueError("Invalid padding")
    return data[:-pad_len]


def encrypt(data: bytes) -> bytes:
    iv = get_random_bytes(16)
    cipher = AES.new(MASTER_KEY, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(data))


def decrypt(enc_data: bytes) -> bytes:
    iv = enc_data[:16]
    cipher = AES.new(MASTER_KEY, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc_data[16:]))


def save_keys(hospital_id: str, public_key: int, private_key: tuple):
    if not os.path.exists(STORAGE_DIR):
        os.makedirs(STORAGE_DIR)
    with open(f'{STORAGE_DIR}/{hospital_id}_public.json', 'w') as f:
        json.dump({'n': str(public_key)}, f)
    priv_bytes = f"{private_key[0]},{private_key[1]}".encode()
    with open(f'{STORAGE_DIR}/{hospital_id}_private.bin', 'wb') as f:
        f.write(encrypt(priv_bytes))


def load_private_key(hospital_id: str) -> tuple:
    with open(f'{STORAGE_DIR}/{hospital_id}_private.bin', 'rb') as f:
        data = decrypt(f.read()).decode()
        p, q = data.split(',')
        return int(p), int(q)


def generate_prime(bits: int) -> int:
    while True:
        p = number.getPrime(bits)
        if p % 4 == 3:
            return p


def generate_rabin_keys(bits=KEY_SIZE) -> tuple:
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    return n, (p, q)


def log_action(hospital_id: str, action: str):
    timestamp = datetime.now(timezone.utc).isoformat()
    logging.info(f"{action} for {hospital_id} at {timestamp}")
    print(f"[{timestamp}] {action} for {hospital_id}")


# === CORE ===

def generate_keys(hospital_id: str):
    if hospital_id in hospital_db and hospital_db[hospital_id]['status'] == 'active':
        raise Exception("Keys already exist for hospital")
    n, (p, q) = generate_rabin_keys()
    save_keys(hospital_id, n, (p, q))
    hospital_db[hospital_id] = {
        'public_key': n,
        'status': 'active',
        'last_renewed': datetime.now(timezone.utc)
    }
    log_action(hospital_id, "Key generation")
    return n


def revoke_keys(hospital_id: str):
    if hospital_id not in hospital_db or hospital_db[hospital_id]['status'] != 'active':
        raise Exception("No active keys to revoke")
    hospital_db[hospital_id]['status'] = 'revoked'
    log_action(hospital_id, "Key revocation")


def renew_keys(hospital_id: str):
    if hospital_id not in hospital_db or hospital_db[hospital_id]['status'] != 'active':
        raise Exception("No active keys to renew")
    n, (p, q) = generate_rabin_keys()
    save_keys(hospital_id, n, (p, q))
    hospital_db[hospital_id]['public_key'] = n
    hospital_db[hospital_id]['last_renewed'] = datetime.now(timezone.utc)
    log_action(hospital_id, "Key renewal")
    return n


def get_keys(hospital_id: str):
    if hospital_id not in hospital_db or hospital_db[hospital_id]['status'] != 'active':
        raise Exception("Keys not found or revoked")
    n = hospital_db[hospital_id]['public_key']
    p, q = load_private_key(hospital_id)
    log_action(hospital_id, "Key distribution")
    return {'public_key': n, 'private_key': (p, q)}


def scheduled_renewal():
    while True:
        now = datetime.now(timezone.utc)
        for hospital_id, info in list(hospital_db.items()):
            if info['status'] == 'active':
                delta = now - info['last_renewed']
                if delta.days >= KEY_RENEWAL_DAYS:
                    try:
                        renew_keys(hospital_id)
                    except Exception as e:
                        logging.error(f"Renewal failed for {hospital_id}: {e}")
        time.sleep(60)  # check every 60 seconds (adjust as needed)


# === TRADE-OFF ANALYSIS ===
"""
Trade-off Rabin vs RSA:

- Rabin:
  + Faster encryption (just squaring)
  + Security based on factoring
  - Decryption ambiguity (4 possible plaintexts)
  - Less flexible padding/signature schemes
  - Less widely adopted

- RSA:
  + Widely supported, standard padding, signatures
  - Slower encryption/decryption

For healthcare, RSA is industry standard, but Rabin is a valid alternative if implemented carefully.
"""


# === SIMPLE CLI INTERFACE ===

def print_menu():
    print("\nCentralized Rabin Key Management System")
    print("1. Generate Keys for Hospital/Clinic")
    print("2. Get Keys")
    print("3. Revoke Keys")
    print("4. Renew Keys")
    print("5. Exit")


def main():
    # Start scheduled renewal in background
    threading.Thread(target=scheduled_renewal, daemon=True).start()

    while True:
        print_menu()
        choice = input("Enter choice: ").strip()
        if choice == '1':
            hid = input("Enter hospital/clinic ID: ").strip()
            try:
                n = generate_keys(hid)
                print(f"Keys generated. Public key (n): {n}")
            except Exception as e:
                print("Error:", e)
        elif choice == '2':
            hid = input("Enter hospital/clinic ID: ").strip()
            try:
                keys = get_keys(hid)
                print("Public key (n):", keys['public_key'])
                print("Private key (p, q):", keys['private_key'])
            except Exception as e:
                print("Error:", e)
        elif choice == '3':
            hid = input("Enter hospital/clinic ID: ").strip()
            try:
                revoke_keys(hid)
                print("Keys revoked successfully.")
            except Exception as e:
                print("Error:", e)
        elif choice == '4':
            hid = input("Enter hospital/clinic ID: ").strip()
            try:
                n = renew_keys(hid)
                print(f"Keys renewed. New public key (n): {n}")
            except Exception as e:
                print("Error:", e)
        elif choice == '5':
            print("Exiting...")
            break
        else:
            print("Invalid choice")


if __name__ == '__main__':
    main()
