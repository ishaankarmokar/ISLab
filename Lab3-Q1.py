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

'''Original message: Asymmetric Encryption
Encrypted message (hex): 39cfa3a91c7d13dfd687c1b1d533b7f9370a92a28c6f67bf763fff85f1e156d0247d3d47e3dc16a2d5ef56f7300316519b63f7eb28ce745990e16b063ba755da80534a24c73f6c80d51b29893ebdebda327f8ccea27cbb31083069be15b40604a222ac3acd2904b81fded0ff59385424d38b94ec65fbb96b46d71117af27d7779954cf6f65369d50ab194fd445aec71091a6e1dffec7bc692efb2549cff616162080273e47042d6806d6ac2ce617fbc938f00d1e744a8791356ee071b32ca79249c0a9ce69f49d215becd90aa827bd4b99896fb537a9f77af5ac85ce9546a8076ef9266ee166567bcbbb5e3580205f508ef4ef8f052be432e1083b28a81cb1bb
Decrypted message: Asymmetric Encryption'''
