import random

def diffie_hellman_key_exchange():
    # Using small prime for simplicity (use larger primes in real life!)
    p = 23  # prime modulus
    g = 5   # generator

    # Alice's private and public keys
    a = random.randint(1, p-1)
    A = pow(g, a, p)

    # Bob's private and public keys
    b = random.randint(1, p-1)
    B = pow(g, b, p)

    # Shared secrets
    alice_shared = pow(B, a, p)
    bob_shared = pow(A, b, p)

    print(f"Alice's public key: {A}")
    print(f"Bob's public key: {B}")
    print(f"Alice's shared secret: {alice_shared}")
    print(f"Bob's shared secret: {bob_shared}")
    print(f"Shared secrets match? {alice_shared == bob_shared}")

diffie_hellman_key_exchange()
