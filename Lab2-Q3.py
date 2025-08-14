from Crypto.Cipher import DES, AES
import time

def pad(msg, block_size):
    while len(msg) % block_size != 0:
        msg += ' '
    return msg

def des_encrypt(message, key):
    key_bytes = key.encode('utf-8')
    message_padded = pad(message, 8)
    cipher = DES.new(key_bytes, DES.MODE_ECB)
    return cipher.encrypt(message_padded.encode('utf-8'))

def des_decrypt(ciphertext, key):
    key_bytes = key.encode('utf-8')
    cipher = DES.new(key_bytes, DES.MODE_ECB)
    decrypted_bytes = cipher.decrypt(ciphertext)
    return decrypted_bytes.decode('utf-8').rstrip()

def aes256_encrypt(message, key_hex):
    key_bytes = bytes.fromhex(key_hex)
    message_padded = pad(message, 16)
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    return cipher.encrypt(message_padded.encode('utf-8'))

def aes256_decrypt(ciphertext, key_hex):
    key_bytes = bytes.fromhex(key_hex)
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    decrypted_bytes = cipher.decrypt(ciphertext)
    return decrypted_bytes.decode('utf-8').rstrip()

# main body
message = "Performance Testing of Encryption Algorithms"

des_key = "A1B2C3D4"  # 8 chars
aes256_key = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"  # 64 hex chars (32 bytes)

# DES encryption time
start_des_enc = time.time()
des_ciphertext = des_encrypt(message, des_key)
end_des_enc = time.time()

# DES decryption time
start_des_dec = time.time()
des_plaintext = des_decrypt(des_ciphertext, des_key)
end_des_dec = time.time()

# AES-256 encryption time
start_aes_enc = time.time()
aes_ciphertext = aes256_encrypt(message, aes256_key)
end_aes_enc = time.time()

# AES-256 decryption time
start_aes_dec = time.time()
aes_plaintext = aes256_decrypt(aes_ciphertext, aes256_key)
end_aes_dec = time.time()

print("DES encryption time: {:.6f} seconds".format(end_des_enc - start_des_enc))
print("DES decryption time: {:.6f} seconds".format(end_des_dec - start_des_dec))
print("AES-256 encryption time: {:.6f} seconds".format(end_aes_enc - start_aes_enc))
print("AES-256 decryption time: {:.6f} seconds".format(end_aes_dec - start_aes_dec))

print("\nDES decrypted message:", des_plaintext)
print("AES-256 decrypted message:", aes_plaintext)
