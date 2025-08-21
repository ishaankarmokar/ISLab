from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

key = RSA.generate(2048)

public_key = key.publickey()
private_key = key

def rsaEncrypt(message, pub_key):
    cipher = PKCS1_OAEP.new(pub_key)         # create cipher with public key and OAEP padding
    ciphertext = cipher.encrypt(message.encode('utf-8'))  # encrypt bytes
    return ciphertext

def rsaDecrypt(ciphertext, priv_key):
    cipher = PKCS1_OAEP.new(priv_key)        # create cipher with private key
    plaintext_bytes = cipher.decrypt(ciphertext)           # decrypt
    return plaintext_bytes.decode('utf-8')

# Main body
message = "Asymmetric Encryption"
print("Original message:", message)

ciphertext = rsaEncrypt(message, public_key)
print("Encrypted message (hex):", ciphertext.hex())

decrypted_message = rsaDecrypt(ciphertext, private_key)
print("Decrypted message:", decrypted_message)
