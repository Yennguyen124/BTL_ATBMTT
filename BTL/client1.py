import socket
import json
import threading
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import base64
import os
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad
import hashlib

# Biến toàn cục
session_key = None
private_key = None
public_key_client2 = None  # public key của client2 để mã hóa session key

def send_to_server1(packet):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('127.0.0.1', 12345))  # Server1
    s.sendall(json.dumps(packet).encode())
    s.close()

# Lắng nghe server1 chuyển tiếp các gói đến client1 (port riêng)
def listen_all():
    global public_key_client2
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', 12348))  # Nhận gói từ Server1
    s.listen(5)
    print("Client1: Đang lắng nghe các gói tin trả về qua Server1...")

    while True:
        conn, _ = s.accept()
        data = conn.recv(4096)
        if data:
            try:
                packet = json.loads(data.decode())
                t = packet.get("type")
                if t == "READY":
                    print("Client1 nhận được READY từ Server!")
                elif t == "PUBLIC_KEY":
                    # Nhận public key của client2 (qua server)
                    print("Client1 nhận được Public Key của Client2 qua server.")
                    pub_bytes = base64.b64decode(packet["public_key"])
                    public_key_client2 = serialization.load_pem_public_key(pub_bytes)
                    # Lưu vào biến toàn cục để dùng mã hóa session key
                    listen_all.public_key_client2 = public_key_client2
                elif t == "ACK":
                    print("==> Client1 nhận được ACK (File đã được nhận và xác thực OK)!")
                elif t == "NACK":
                    print("==> Client1 nhận được NACK (Dữ liệu hoặc chữ ký không hợp lệ!)")
                else:
                    print("Client1 nhận được:", packet)
            except Exception as e:
                print("Client1 nhận gói không hợp lệ hoặc lỗi:", e)
        conn.close()

def send_hello():
    hello_packet = {
        "type": "HELLO",
        "from": "client1",
        "to": "client2",
        "msg": "Hello!"
    }
    send_to_server1(hello_packet)
    print("Client1 đã gửi HELLO (qua Server1).")

def send_public_key():
    global private_key
    if private_key is None:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    packet = {
        "type": "PUBLIC_KEY",
        "from": "client1",
        "to": "client2",
        "public_key": base64.b64encode(public_bytes).decode()
    }
    send_to_server1(packet)
    print("Client1 đã gửi PUBLIC_KEY cho Client2 (qua Server1).")

def send_session_key():
    # Đảm bảo đã nhận được public key của client2
    global session_key
    public_key2 = getattr(listen_all, 'public_key_client2', None)
    if public_key2 is None:
        print("Chưa nhận được public key của client2! Hãy chờ hoặc nhận lại qua server.")
        return

    session_key = os.urandom(8)
    print("Session Key trước khi mã hóa:", session_key.hex())
    metadata = b'legal_doc.txt|2025-07-01T13:00:00|12345'
    signature = private_key.sign(
        metadata,
        padding.PKCS1v15(),
        hashes.SHA512()
    )
    encrypted_session_key = public_key2.encrypt(
        session_key, padding.PKCS1v15()
    )
    print("Session Key sau khi mã hóa:", base64.b64encode(encrypted_session_key).decode())

    packet = {
        "type": "SESSION_KEY",
        "from": "client1",
        "to": "client2",
        "metadata": base64.b64encode(metadata).decode(),
        "signature": base64.b64encode(signature).decode(),
        "encrypted_session_key": base64.b64encode(encrypted_session_key).decode()
    }
    send_to_server1(packet)
    print("Client1 đã gửi SESSION_KEY cho Client2 (qua Server1).")

def send_file_encrypted():
    global session_key
    if not session_key:
        print("Chưa có session key, không thể gửi file!")
        return
    file_path = 'legal_doc.txt'
    if not os.path.exists(file_path):
        print(f"File {file_path} không tồn tại!")
        return
    iv = os.urandom(8)
    with open(file_path, 'rb') as f:
        file_data = f.read()
    cipher = DES.new(session_key, DES.MODE_CBC, iv)
    padded_data = pad(file_data, 8)
    ciphertext = cipher.encrypt(padded_data)
    print(f"Ciphertext (Base64): {base64.b64encode(ciphertext).decode()}")
    iv_and_ciphertext = iv + ciphertext
    hash_value = hashlib.sha512(iv_and_ciphertext).hexdigest()
    print(f"Hash SHA-512 (Hex): {hash_value}")
    signature = private_key.sign(
        hash_value.encode(),
        padding.PKCS1v15(),
        hashes.SHA512()
    )
    print(f"Signature (Base64): {base64.b64encode(signature).decode()}")
    print(f"IV (Base64): {base64.b64encode(iv).decode()}")
    packet = {
        "type": "FILE",
        "from": "client1",
        "to": "client2",
        "iv": base64.b64encode(iv).decode(),
        "cipher": base64.b64encode(ciphertext).decode(),
        "hash": hash_value,
        "sig": base64.b64encode(signature).decode()
    }
    send_to_server1(packet)
    print("Client1 đã gửi file mã hóa (qua Server1).")

def menu():
    print("1. Gửi HELLO")
    print("2. Gửi PUBLIC KEY (trao khóa)")
    print("3. Gửi SESSION KEY")
    print("4. Mã hóa và gửi file đã mã hóa")
    while True:
        choice = input("Chọn chức năng (1/2/3/4): ")
        if choice == '1':
            send_hello()
        elif choice == '2':
            send_public_key()
        elif choice == '3':
            send_session_key()
        elif choice == '4':
            send_file_encrypted()
        else:
            print("Nhập lại!")

if __name__ == "__main__":
    threading.Thread(target=listen_all, daemon=True).start()
    threading.Thread(target=menu, daemon=True).start()
    while True:
        time.sleep(1)
