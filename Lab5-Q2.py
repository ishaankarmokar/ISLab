import socket
import sys
import threading
import time


def custom_hash(input_string: str) -> int:
    hash_value = 5381
    for char in input_string:
        hash_value = (hash_value * 33) + ord(char)
        hash_value = hash_value ^ (hash_value >> 16)
    return hash_value & 0xFFFFFFFF


def start_server(host='127.0.0.1', port=65432):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f'Server listening on {host}:{port}...')
        while True:
            conn, addr = s.accept()
            with conn:
                print(f'Connected by {addr}')
                data = conn.recv(1024)
                if not data:
                    print("No data received.")
                    continue
                received_text = data.decode()
                print(f'Received data: {received_text}')

                # Compute hash of received data
                data_hash = custom_hash(received_text)
                print(f'Computed hash on server: {data_hash:#010x}')

                # Send hash back to client as string
                conn.sendall(str(data_hash).encode())


def send_data(data, host='127.0.0.1', port=65432, corrupt=False):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))

        # Optionally corrupt data to simulate tampering
        send_data_str = data
        if corrupt:
            send_data_str = data[:-1] + chr((ord(data[-1]) + 1) % 256)
            print(f"Data corrupted before sending: {send_data_str}")
        else:
            print(f"Data sent: {send_data_str}")

        s.sendall(send_data_str.encode())

        # Compute local hash of original data (not corrupted)
        local_hash = custom_hash(data)
        print(f'Local computed hash: {local_hash:#010x}')

        # Receive hash from server
        server_hash_bytes = s.recv(1024)
        server_hash = int(server_hash_bytes.decode())
        print(f'Hash received from server: {server_hash:#010x}')

        # Verify integrity
        if local_hash == server_hash:
            print("Data integrity verified: Hashes match!")
        else:
            print("Data integrity check failed: Hashes do NOT match!")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python Lab5-Q2.py [server|client]")
        sys.exit(1)

    mode = sys.argv[1].lower()
    if mode == 'server':
        start_server()
    elif mode == 'client':
        # Normal transmission
        send_data("Hello, server!")

        print("\n--- Now simulating corrupted data transmission ---\n")

        # Corrupted transmission
        send_data("Hello, server!", corrupt=True)
    else:
        print("Invalid mode. Use 'server' or 'client'.")

'''
Data sent: Hello, server!
Hash received from server: 0xe3142811
Data integrity verified: Hashes match!

--- Now simulating corrupted data transmission ---

Data corrupted before sending: Hello, server"
Local computed hash: 0xe3142811
Hash received from server: 0xe314280e
Data integrity check failed: Hashes do NOT match!

'''