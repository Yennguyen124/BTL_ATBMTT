import socket
import json
import base64
import hashlib
import threading
import time
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

private_key = None
session_key = None
public_key_client1 = None  # Lưu public key của Client1

def listen_all():
    global session_key, public_key_client1, private_key
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', 12347))   # Client2 luôn lắng nghe ở port này
    s.listen(5)
    print("Client2: Đang lắng nghe trên port 12347...")

    while True:
        conn, _ = s.accept()
        data = conn.recv(16384)
        if data:
            try:
                packet = json.loads(data.decode())
                t = packet.get("type")
                if t == "HELLO":
                    print("Client2 nhận được HELLO!")
                    send_ready()
                elif t == "PUBLIC_KEY":
                    print("Client2 nhận được PUBLIC_KEY từ Client1 qua server!")
                    pub_bytes = base64.b64decode(packet["public_key"])
                    public_key_client1 = serialization.load_pem_public_key(pub_bytes, backend=default_backend())
                    print("Đã lưu public key của Client1.")
                elif t == "SESSION_KEY":
                    print("Client2 nhận được SESSION_KEY!")
                    if private_key:
                        encrypted_session_key = base64.b64decode(packet["encrypted_session_key"])
                        session_key = private_key.decrypt(encrypted_session_key, padding.PKCS1v15())
                        print("Session key đã giải mã (hex):", session_key.hex())
                    else:
                        print("Chưa có private key để giải mã session key!")
                elif t == "FILE":
                    print("Client2 nhận được FILE từ Client1!")
                    receive_file(packet)
                elif t in ["ACK", "NACK"]:
                    print(f"Nhận được phản hồi từ phía khác: {packet}")
                else:
                    print("Nhận gói tin lạ:", packet)
            except Exception as e:
                print("Lỗi khi xử lý gói tin:", e)
        conn.close()

def send_ready():
    ready_packet = {
        "type": "READY",
        "from": "client2",
        "to": "client1",
        "msg": "Ready!"
    }
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('127.0.0.1', 12346))  # Gửi lên server2
    s.sendall(json.dumps(ready_packet).encode())
    s.close()
    print("Client2 đã gửi READY qua server2.")

def send_public_key():
    global private_key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    packet = {
        "type": "PUBLIC_KEY",
        "from": "client2",
        "to": "client1",
        "public_key": base64.b64encode(public_bytes).decode()
    }
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('127.0.0.1', 12346))  # Gửi lên server2
    s.sendall(json.dumps(packet).encode())
    s.close()
    print("Client2 đã gửi PUBLIC_KEY cho client1 (qua server2).")

def check_integrity(iv, ciphertext, hash_value, signature):
    global public_key_client1
    iv_and_ciphertext = iv + ciphertext
    computed_hash = hashlib.sha512(iv_and_ciphertext).hexdigest()
    if computed_hash != hash_value:
        print("Hash không hợp lệ!")
        return False
    if public_key_client1 is None:
        print("Chưa nhận được public key của Client1!")
        return False
    try:
        public_key_client1.verify(
            base64.b64decode(signature),
            hash_value.encode(),
            padding.PKCS1v15(),
            hashes.SHA512()
        )
        print("Chữ ký hợp lệ.")
        return True
    except Exception as e:
        print(f"Chữ ký không hợp lệ: {e}")
        return False

def decrypt_and_save_file(iv, ciphertext, session_key):
    cipher = DES.new(session_key, DES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), 8)
    with open("legal_doc_received.txt", "wb") as f:
        f.write(decrypted_data)
    print("Đã giải mã và lưu file legal_doc_received.txt")

def receive_file(packet):
    global session_key
    iv = base64.b64decode(packet["iv"])
    ciphertext = base64.b64decode(packet["cipher"])
    hash_value = packet["hash"]
    signature = packet["sig"]

    print("IV (Base64):", packet["iv"])
    print("Ciphertext (Base64):", packet["cipher"])
    print("Hash (SHA-512):", hash_value)
    print("Signature (Base64):", packet["sig"])

    if session_key is None:
        print("Chưa có session key để giải mã file!")
        return
    if check_integrity(iv, ciphertext, hash_value, signature):
        decrypt_and_save_file(iv, ciphertext, session_key)
        send_ack()
    else:
        send_nack()

def send_ack():
    ack_packet = {
        "type": "ACK",
        "from": "client2",
        "to": "client1",  # Gửi về client1 qua server2/server1
        "msg": "Integrity check passed. File received & saved."
    }
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('127.0.0.1', 12346))
    s.sendall(json.dumps(ack_packet).encode())
    s.close()
    print("Client2 đã gửi ACK về server2.")

def send_nack():
    nack_packet = {
        "type": "NACK",
        "from": "client2",
        "to": "client1",
        "msg": "Integrity check failed. File not accepted."
    }
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('127.0.0.1', 12346))
    s.sendall(json.dumps(nack_packet).encode())
    s.close()
    print("Client2 đã gửi NACK về server2.")

def menu():
    print("1. Gửi READY (sau khi nhận HELLO)")
    print("2. Gửi Public Key (trao khóa RSA)")
    print("3. Đợi nhận Session Key và giải mã session key")
    print("4. Đợi nhận file và tự động xác thực/giải mã file")
    while True:
        choice = input("Chọn chức năng (1/2/3/4): ")
        if choice == '1':
            print("Chờ nhận HELLO để tự động gửi READY...")
        elif choice == '2':
            send_public_key()
        elif choice == '3':
            print("Đợi SESSION_KEY, sẽ tự động giải mã khi nhận được!")
        elif choice == '4':
            print("Đợi nhận file từ Client1 gửi qua server...")
        else:
            print("Nhập lại!")

if __name__ == "__main__":
    threading.Thread(target=listen_all, daemon=True).start()
    threading.Thread(target=menu, daemon=True).start()
    while True:
        time.sleep(1)
