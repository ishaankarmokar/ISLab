from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

message = b"Top Secret Data"

key_hex = "FEDCBA9876543210FEDCBA9876543210"

# Convert the hex key to bytes
key = bytes.fromhex(key_hex)

# Encryption
# Padding
cipher = AES.new(key, AES.MODE_ECB)

# Encrypt the message
ciphertext = cipher.encrypt(pad(message, AES.block_size))

print(f"Original message: {message}")
print(f"Ciphertext (hex): {ciphertext.hex()}")

# Decryption
# Create a new AES cipher object for decryption
cipher_decrypt = AES.new(key, AES.MODE_ECB)

# Decrypt the ciphertext and unpad it to get the original message
decrypted_message = unpad(cipher_decrypt.decrypt(ciphertext), AES.block_size)

print(f"Decrypted message: {decrypted_message}")

# Verification
if decrypted_message == message:
    print("\nVerification successful: The decrypted message matches the original.")
else:
    print("\nVerification failed: The decrypted message does not match the original.")