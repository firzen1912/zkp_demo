import socket
import random
import json
from hashlib import sha256

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def fiat_shamir_challenge(x, n):
    h = sha256()
    h.update(str(x).encode() + str(n).encode())
    return h.digest()[-1] & 1

# Key generation
p = 499
q = 547
n = p * q
s = random.randint(2, n - 1)
while gcd(s, n) != 1:
    s = random.randint(2, n - 1)
v = pow(s, 2, n)  # Public value, shared with server in advance

def create_proof(s, n, v):
    r = random.randint(2, n - 1)
    x = pow(r, 2, n)
    e = fiat_shamir_challenge(x, n)
    y = r if e == 0 else (r * s) % n
    return {'x': x, 'y': y, 'e': e}

proof = create_proof(s, n, v)

HOST = '127.0.0.1'
PORT = 65432

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(json.dumps(proof).encode())
    data = s.recv(1024)

print('Server response:', data.decode())
