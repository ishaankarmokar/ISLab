from Crypto.Cipher import DES

key = b"A1B2C3D4"

message = "Confidential Data"

def pad(msg):
    while len(msg) % 8 != 0:
        msg += ' '
    return msg

message_padded = pad(message)

des_cipher = DES.new(key, DES.MODE_ECB)

ciphertext = des_cipher.encrypt(message_padded.encode('utf-8'))

decrypted_bytes = des_cipher.decrypt(ciphertext)
decrypted_message = decrypted_bytes.decode('utf-8').rstrip()  # strip padding spaces

print("Original message:", message)
print("Encrypted (hex):", ciphertext.hex())
print("Decrypted message:", decrypted_message)
