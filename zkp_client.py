# srp_client.py
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

def H(*args):
    h = hashlib.sha256()
    for arg in args:
        h.update(arg if isinstance(arg, bytes) else str(arg).encode())
    return int.from_bytes(h.digest(), 'big')

def calculate_x(salt, I, P):
    return H(salt, H(f"{I}:{P}"))

def register(username, password):
    with socket.socket() as s:
        s.connect(('localhost', 8000))
        s.sendall(pickle.dumps({
            'type': 'register',
            'username': username,
            'password': password
        }))
        response = pickle.loads(s.recv(4096))
        if response['status'] == 'ok':
            print("[+] Registration successful!")
        else:
            print("[-] Registration failed:", response['msg'])

def login(username, password):
    a = secrets.randbelow(N)
    A = pow(g, a, N)

    with socket.socket() as s:
        s.connect(('localhost', 8000))
        s.sendall(pickle.dumps({
            'type': 'login',
            'username': username,
            'A': A
        }))

        response = pickle.loads(s.recv(4096))
        if response['status'] != 'ok':
            print("[-] Login failed:", response['msg'])
            return

        salt = response['salt']
        B = response['B']
        u = H(A, B)
        x = calculate_x(salt, username, password)
        S = pow(B - k * pow(g, x, N), a + u * x, N)
        K_client = H(S)
        print("[+] Client session key:", hex(K_client))

def main():
    choice = input("Register or Login? [r/l]: ").strip().lower()
    username = input("Username: ").strip()
    password = input("Password: ").strip()

    if choice == 'r':
        register(username, password)
    elif choice == 'l':
        login(username, password)
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
