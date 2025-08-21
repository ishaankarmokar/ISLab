import os, time
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def aes_gcm_encrypt(key, plaintext):
    iv = os.urandom(12)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv, ciphertext, encryptor.tag

def aes_gcm_decrypt(key, iv, ciphertext, tag):
    decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def rsa_keygen():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    return priv, priv.public_key()

def rsa_encrypt(pub, msg):
    return pub.encrypt(msg, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

def rsa_decrypt(priv, ct):
    return priv.decrypt(ct, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

def ecc_keygen():
    priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
    return priv, priv.public_key()

def ecc_derive_key(priv, pub):
    shared = priv.exchange(ec.ECDH(), pub)
    return HKDF(hashes.SHA256(), 32, None, b'handshake data', default_backend()).derive(shared)

def ecc_encrypt(sender_priv, receiver_pub, msg):
    key = ecc_derive_key(sender_priv, receiver_pub)
    return aes_gcm_encrypt(key, msg)

def ecc_decrypt(receiver_priv, sender_pub, iv, ct, tag):
    key = ecc_derive_key(receiver_priv, sender_pub)
    return aes_gcm_decrypt(key, iv, ct, tag)

def measure():
    sizes = [1024, 10*1024]
    print("RSA 2048-bit key generation...")
    start = time.time()
    rsa_priv, rsa_pub = rsa_keygen()
    print(f"Key gen time: {time.time()-start:.4f}s\n")

    for size in sizes:
        msg = os.urandom(size)
        aes_key = os.urandom(32)
        start = time.time()
        iv, ct, tag = aes_gcm_encrypt(aes_key, msg)
        enc_key = rsa_encrypt(rsa_pub, aes_key)
        print(f"RSA Encrypt {size//1024}KB: {time.time()-start:.4f}s")

        start = time.time()
        dec_key = rsa_decrypt(rsa_priv, enc_key)
        pt = aes_gcm_decrypt(dec_key, iv, ct, tag)
        print(f"RSA Decrypt {size//1024}KB: {time.time()-start:.4f}s")
        assert pt == msg

    print("\nECC (ECDH + AES-GCM) key generation...")
    start = time.time()
    ecc_priv1, ecc_pub1 = ecc_keygen()
    ecc_priv2, ecc_pub2 = ecc_keygen()
    print(f"Key gen time (both): {time.time()-start:.4f}s\n")

    for size in sizes:
        msg = os.urandom(size)
        start = time.time()
        iv, ct, tag = ecc_encrypt(ecc_priv1, ecc_pub2, msg)
        print(f"ECC Encrypt {size//1024}KB: {time.time()-start:.4f}s")

        start = time.time()
        pt = ecc_decrypt(ecc_priv2, ecc_pub1, iv, ct, tag)
        print(f"ECC Decrypt {size//1024}KB: {time.time()-start:.4f}s")
        assert pt == msg

measure()

'''RSA 2048-bit key generation...
Key gen time: 0.0658s

RSA Encrypt 1KB: 0.0010s
RSA Decrypt 1KB: 0.0020s
RSA Encrypt 10KB: 0.0000s
RSA Decrypt 10KB: 0.0010s

ECC (ECDH + AES-GCM) key generation...
Key gen time (both): 0.0000s

ECC Encrypt 1KB: 0.0000s
ECC Decrypt 1KB: 0.0000s
ECC Encrypt 10KB: 0.0000s
ECC Decrypt 10KB: 0.0000s'''