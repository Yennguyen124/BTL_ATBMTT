import socket
from datetime import datetime
import json

def log(msg):
    with open("server1_log.txt", "a", encoding="utf-8") as f:
        f.write(f"{datetime.now()} - {msg}\n")

def server1():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', 12345))
    s.listen(5)
    print("Server1 listening on 12345...")

    while True:
        conn, addr = s.accept()
        data = conn.recv(16384)
        if data:
            msg = data.decode(errors="ignore")
            log(f"Nhận từ {addr}: {msg}")
            try:
                packet = json.loads(msg)
                # Phân luồng forward dựa vào trường 'to'
                if packet.get("to") == "server2":
                    # Gói tin từ client2 chuyển về client1 (ACK/NACK)
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2:
                        s2.connect(('127.0.0.1', 12346))
                        s2.sendall(data)
                        log(f"Forward ACK/NACK tới server2: {msg}")
                elif packet.get("to") == "client1":
                    # Server1 nhận phản hồi từ server2 chuyển cho client1
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_c1:
                        s_c1.connect(('127.0.0.1', 12348))
                        s_c1.sendall(data)
                        log(f"Forward ACK/NACK tới client1: {msg}")
                else:
                    # Mặc định forward sang server2
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2:
                        s2.connect(('127.0.0.1', 12346))
                        s2.sendall(data)
                        log(f"Forward tới server2: {msg}")
            except Exception as e:
                log(f"Lỗi parse JSON: {e}")
        conn.close()

if __name__ == "__main__":
    server1()
