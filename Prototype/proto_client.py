# client.py (fingerprint-based)
import socket
import json
import random
import os
from math import gcd
import platform
import uuid
import hashlib

def get_device_fingerprint():
    info = platform.uname()
    device_id = f"{info.system}-{info.node}-{info.machine}-{info.processor}-{uuid.getnode()}"
    return hashlib.sha256(device_id.encode()).hexdigest()

def generate_keys():
    p = 499
    q = 547
    n = p * q
    s = random.randint(2, n - 1)
    while gcd(s, n) != 1:
        s = random.randint(2, n - 1)
    v = pow(s, 2, n)
    return s, v, n

def register(fingerprint):
    s, v, n = generate_keys()
    with open(f"{fingerprint}_secret.json", "w") as f:
        json.dump({"s": s, "n": n}, f)

    request = {
        "type": "register",
        "username": fingerprint,
        "v": v,
        "n": n
    }

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sckt:
        sckt.connect(('127.0.0.1', 65432))
        sckt.sendall(json.dumps(request).encode())
        response = sckt.recv(1024)
        print("[*] Server response:", response.decode())

def authenticate(fingerprint, rounds=5):
    if not os.path.exists(f"{fingerprint}_secret.json"):
        print("[!] You must register this device first.")
        return

    with open(f"{fingerprint}_secret.json") as f:
        secret_data = json.load(f)
        s = secret_data["s"]
        n = secret_data["n"]

    round_data = []
    rs = []

    for _ in range(rounds):
        r = random.randint(2, n - 1)
        x = pow(r, 2, n)
        rs.append(r)
        round_data.append({"x": x})

    request = {
        "type": "authenticate",
        "username": fingerprint,
        "rounds": round_data
    }

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sckt:
        sckt.connect(('127.0.0.1', 65432))
        sckt.sendall(json.dumps(request).encode())

        # Step 2: Get challenges
        response = json.loads(sckt.recv(4096).decode())
        es = response["challenges"]

        # Step 3: Send responses
        ys = []
        for i in range(rounds):
            y = rs[i] if es[i] == 0 else (rs[i] * s) % n
            ys.append(y)

        sckt.sendall(json.dumps({"ys": ys}).encode())
        result = sckt.recv(1024).decode()
        print("[*] Authentication result:", result)

# === Main UI ===
fingerprint = get_device_fingerprint()
print(f"[*] Device fingerprint: {fingerprint[:16]}...")

mode = input("Do you want to [r]egister or [a]uthenticate this device? ").strip().lower()

if mode == "r":
    register(fingerprint)
elif mode == "a":
    authenticate(fingerprint)
else:
    print("Invalid option.")
