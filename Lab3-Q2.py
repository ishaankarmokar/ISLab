from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from binascii import hexlify
from Crypto.Random import get_random_bytes

private_key = ECC.generate(curve='P-256')
public_key = private_key.public_key()

def encrypt_message(pub_key, message):
    ephemeral_key = ECC.generate(curve='P-256')
    shared_secret_point = ephemeral_key.d * pub_key.pointQ
    shared_secret = int(shared_secret_point.x).to_bytes(32, 'big')
    derived_key = HKDF(shared_secret, 32, None, SHA256)
    iv = get_random_bytes(16)
    cipher = AES.new(derived_key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(message)
    return ephemeral_key.public_key(), iv, ciphertext, tag

def decrypt_message(priv_key, eph_pub_key, iv, ciphertext, tag):
    shared_secret_point = priv_key.d * eph_pub_key.pointQ
    shared_secret = int(shared_secret_point.x).to_bytes(32, 'big')
    derived_key = HKDF(shared_secret, 32, None, SHA256)
    cipher = AES.new(derived_key, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ciphertext, tag)

message = b"Secure Transactions"
eph_pub_key, iv, ciphertext, tag = encrypt_message(public_key, message)
decrypted = decrypt_message(private_key, eph_pub_key, iv, ciphertext, tag)

print("Plain text:", message.decode())
print("Ciphertext:", hexlify(ciphertext).decode())
print("Decrypted text:", decrypted.decode())
print("Successful" if decrypted == message else "Unsuccessful")
