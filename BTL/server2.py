import socket
from datetime import datetime
import json

def log(msg):
    with open("server2_log.txt", "a", encoding="utf-8") as f:
        f.write(f"{datetime.now()} - {msg}\n")

def server2():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', 12346))
    s.listen(5)
    print("Server2 listening on 12346...")

    while True:
        conn, addr = s.accept()
        data = conn.recv(16384)
        if data:
            msg = data.decode(errors="ignore")
            log(f"Nhận từ {addr}: {msg}")
            try:
                packet = json.loads(msg)
                # Phân luồng forward dựa vào trường 'to'
                if packet.get("to") == "client2":
                    dest_port = 12347
                elif packet.get("to") == "client1":
                    dest_port = 12348
                elif packet.get("to") == "server1":
                    # Gói ACK/NACK từ client2 chuyển về server1
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s1:
                        s1.connect(('127.0.0.1', 12345))
                        s1.sendall(data)
                        log(f"Forward về server1: {msg}")
                    conn.close()
                    continue
                else:
                    dest_port = None
                if dest_port:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_dest:
                        s_dest.connect(('127.0.0.1', dest_port))
                        s_dest.sendall(data)
                        log(f"Forward tới cổng {dest_port}: {msg}")
            except Exception as e:
                log(f"Lỗi parse JSON: {e}")
        conn.close()

if __name__ == "__main__":
    server2()
