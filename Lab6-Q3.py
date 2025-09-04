# Server code (verify signature)
import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def sign_message(private_key, message):
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False

# Server listens for message + signature, verifies and responds
def start_server():
    private_key, public_key = generate_rsa_keys()
    print("Server public key generated.")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('localhost', 65432))
        s.listen()
        print("Server listening...")
        conn, addr = s.accept()
        with conn:
            print('Connected by', addr)
            message = conn.recv(1024).decode()
            signature = conn.recv(1024)
            print("Received message:", message)
            print("Verifying signature...")
            if verify_signature(public_key, message, signature):
                conn.sendall(b'Valid Signature')
            else:
                conn.sendall(b'Invalid Signature')

# Client sends message + signature
def start_client(message):
    private_key, public_key = generate_rsa_keys()
    signature = sign_message(private_key, message)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('localhost', 65432))
        s.sendall(message.encode())
        s.sendall(signature)
        response = s.recv(1024)
        print("Server response:", response.decode())

# To run:
# In one terminal: start_server()
# In another terminal: start_client("Hello, server!")

