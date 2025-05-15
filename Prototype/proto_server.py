# server.py
import socket
import json
import random

users = {}

def handle_client(conn):
    data = conn.recv(4096).decode()
    request = json.loads(data)
    action = request.get("type")
    device_id = request.get("username")

    if action == "register":
        v = request["v"]
        n = request["n"]
        users[device_id] = {"v": v, "n": n}
        conn.sendall(b"Registered device successfully.")

    elif action == "authenticate":
        if device_id not in users:
            conn.sendall(b"Device not registered.")
            return

        v = users[device_id]["v"]
        n = users[device_id]["n"]
        rounds = request["rounds"]
        es = [random.randint(0, 1) for _ in rounds]
        conn.sendall(json.dumps({"challenges": es}).encode())

        response = json.loads(conn.recv(4096).decode())
        ys = response["ys"]

        for i in range(len(rounds)):
            x = rounds[i]["x"]
            y = ys[i]
            if es[i] == 0:
                if pow(y, 2, n) != x % n:
                    conn.sendall(b"Authentication failed (challenge 0).")
                    return
            else:
                if pow(y, 2, n) != (x * v) % n:
                    conn.sendall(b"Authentication failed (challenge 1).")
                    return

        conn.sendall(b"Authentication succeeded.")

def start_server():
    HOST = '127.0.0.1'
    PORT = 65432
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[*] Server listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            print(f"[+] Connection from {addr}")
            handle_client(conn)
            conn.close()

if __name__ == "__main__":
    start_server()
