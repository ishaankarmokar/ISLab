from Crypto.Cipher import AES

def pad(msg):
    while len(msg) % 16 != 0:
        msg += ' '
    return msg

def aes_encrypt(message, key_hex):
    key_bytes = bytes.fromhex(key_hex)
    message_padded = pad(message)
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    encrypted_bytes = cipher.encrypt(message_padded.encode('utf-8'))
    return encrypted_bytes

def aes_decrypt(ciphertext, key_hex):
    key_bytes = bytes.fromhex(key_hex)
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    decrypted_bytes = cipher.decrypt(ciphertext)
    decrypted_message = decrypted_bytes.decode('utf-8').rstrip()
    return decrypted_message

# main body
key = "0123456789ABCDEF0123456789ABCDEF"
message = "Sensitive Information"

print("Original message:", message)
ciphertext = aes_encrypt(message, key)
print("Encrypted (hex):", ciphertext.hex())

plaintext = aes_decrypt(ciphertext, key)
print("Decrypted message:", plaintext)
