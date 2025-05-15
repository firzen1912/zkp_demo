import socket
import json
from hashlib import sha256

def fiat_shamir_challenge(x, n):
    h = sha256()
    h.update(str(x).encode() + str(n).encode())
    return h.digest()[-1] & 1

def verify_proof(proof, n, v):
    x, y, e = proof['x'], proof['y'], proof['e']
    lhs = pow(y, 2, n)
    rhs = x if e == 0 else (x * v) % n
    return lhs == rhs

# Public key (generated and shared out-of-band)
n = 499 * 547  # Example small RSA modulus
v = 100301     # Replace with actual v from client keygen

HOST = '127.0.0.1'
PORT = 65432

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(1)
    print("Server is listening...")
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        data = conn.recv(4096)
        proof = json.loads(data.decode())

        print("Received proof:", proof)
        if verify_proof(proof, n, v):
            conn.sendall(b"Authenticated")
        else:
            conn.sendall(b"Rejected")
