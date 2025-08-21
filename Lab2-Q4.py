from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import os

message = b"Classified Text"

key = os.urandom(24)

# Key length ver
if len(key) not in [16, 24]:
    raise ValueError("DES3 key must be 16 or 24 bytes long.")

# Encryption
# The IV (Initialization Vector) must be 8 bytes for DES3
iv = os.urandom(8)
cipher = DES3.new(key, DES3.MODE_CBC, iv)

# Pad the message and encrypt
padded_message = pad(message, DES3.block_size)
ciphertext = cipher.encrypt(padded_message)

print(f"Original message: {message}")
print(f"Ciphertext (hex): {ciphertext.hex()}")

# Decryption
# Use the same key and IV for decryption
cipher_decrypt = DES3.new(key, DES3.MODE_CBC, iv)

# Decrypt the ciphertext and unpad
decrypted_message = unpad(cipher_decrypt.decrypt(ciphertext), DES3.block_size)

print(f"Decrypted message: {decrypted_message}")

