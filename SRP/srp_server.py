# srp_server.py
import socket
import hashlib
import secrets
import pickle

N = int("EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576"
        "D674DF7496EA81D3383B4813D692C6E0E0D5D8E2BAE6E63F4BBE117577A615D6"
        "C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2C"
        "FBE47BDFA5B27F7E2CAAE61434C4EF3E", 16)
g = 2
k = 3

user_db = {}  # In-memory database

def save_user_db_to_file(filename="user_db.txt"):
    with open(filename, "w") as f:
        for username, (salt, v) in user_db.items():
            f.write(f"{username}:{salt.hex()}:{hex(v)}\n")

def load_user_db_from_file(filename="user_db.txt"):
    try:
        with open(filename, "r") as f:
            for line in f:
                username, salt_hex, v_hex = line.strip().split(":")
                salt = bytes.fromhex(salt_hex)
                v = int(v_hex, 16)
                user_db[username] = (salt, v)
        print("[*] Loaded user database from file.")
    except FileNotFoundError:
        print("[*] No user database file found. Starting fresh.")

def H(*args):
    h = hashlib.sha256()
    for arg in args:
        h.update(arg if isinstance(arg, bytes) else str(arg).encode())
    return int.from_bytes(h.digest(), 'big')

def calculate_x(salt, I, P):
    return H(salt, H(f"{I}:{P}"))

def run_server():
    load_user_db_from_file()
    with socket.socket() as s:
        s.bind(('localhost', 8000))
        s.listen(1)
        print("[*] Server listening on port 8000...")

        while True:
            conn, addr = s.accept()
            with conn:
                print(f"\n[*] Connected by {addr}")
                request = pickle.loads(conn.recv(4096))

                if request['type'] == 'register':
                    I, P = request['username'], request['password']
                    if I in user_db:
                        conn.sendall(pickle.dumps({'status': 'error', 'msg': 'User already exists'}))
                        continue
                    salt = secrets.token_bytes(16)
                    x = calculate_x(salt, I, P)
                    v = pow(g, x, N)
                    user_db[I] = (salt, v)
                    save_user_db_to_file()
                    conn.sendall(pickle.dumps({'status': 'ok'}))
                    print(f"[*] Registered user '{I}'")


                elif request['type'] == 'login':
                    I, A = request['username'], request['A']
                    if I not in user_db:
                        conn.sendall(pickle.dumps({'status': 'error', 'msg': 'Unknown user'}))
                        continue
                    salt, v = user_db[I]
                    b = secrets.randbelow(N)
                    B = (k * v + pow(g, b, N)) % N
                    u = H(A, B)
                    S = pow(A * pow(v, u, N), b, N)
                    K_server = H(S)
                    conn.sendall(pickle.dumps({'status': 'ok', 'salt': salt, 'B': B}))
                    print(f"[*] Server session key for '{I}':", hex(K_server))

if __name__ == "__main__":
    run_server()
