from Crypto.Util.number import getPrime, inverse, GCD
import random
import hashlib

# Parameters setup
def generate_elgamal_keys(bits=256):
    p = getPrime(bits)
    g = random.randint(2, p-2)
    x = random.randint(1, p-2)  # private key
    y = pow(g, x, p)  # public key
    return (p, g, y), x

def sign_elgamal(message, private_key, params):
    p, g, y = params
    x = private_key
    m = int.from_bytes(message.encode(), 'big')
    while True:
        k = random.randint(1, p-2)
        if GCD(k, p-1) == 1:
            break
    r = pow(g, k, p)
    k_inv = inverse(k, p-1)
    s = (k_inv * (m - x * r)) % (p - 1)
    return (r, s)

def verify_elgamal(message, signature, public_key):
    p, g, y = public_key
    r, s = signature
    if not (0 < r < p):
        return False
    m = int.from_bytes(message.encode(), 'big')
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, m, p)
    return v1 == v2

def generate_schnorr_keys(q, p, g):
    x = random.randint(1, q-1)  # private key
    y = pow(g, x, p)            # public key
    return (p, q, g, y), x

def hash_function(*args):
    h = hashlib.sha256()
    for arg in args:
        if isinstance(arg, int):
            arg = str(arg).encode()
        elif isinstance(arg, str):
            arg = arg.encode()
        h.update(arg)
    return int(h.hexdigest(), 16)

def sign_schnorr(message, private_key, params):
    p, q, g, y = params
    x = private_key
    k = random.randint(1, q-1)
    r = pow(g, k, p)
    e = hash_function(r, message) % q
    s = (k + x * e) % q
    return (e, s)

def verify_schnorr(message, signature, public_key):
    p, q, g, y = public_key
    e, s = signature
    r = (pow(g, s, p) * pow(y, q - e, p)) % p
    e_prime = hash_function(r, message) % q
    return e == e_prime

params, priv_key = generate_elgamal_keys()
pub_key = params
message = "Hello, ElGamal!"
signature = sign_elgamal(message, priv_key, params)

print("Message:", message)
print("Signature:", signature)
print("Verification:", verify_elgamal(message, signature, pub_key))

p = 208351617316091241234326746312124448251235562226470491514186331217050270460481
q = 104175808658045620617163373156062224125617781113235245757093165608525135230240
g = 2

params, priv_key = generate_schnorr_keys(q, p, g)
pub_key = params
message = "Hello, Schnorr!"
signature = sign_schnorr(message, priv_key, params)

print("Message:", message)
print("Signature:", signature)
print("Verification:", verify_schnorr(message, signature, pub_key))
