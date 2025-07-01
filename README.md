🔐 Hệ thống truyền file bảo mật sử dụng RSA và DES
Đây là một dự án mô phỏng quá trình truyền file an toàn giữa hai client thông qua hai server trung gian, sử dụng mô hình mã hóa lai (hybrid encryption).

🔑 RSA (mã hóa bất đối xứng): để trao đổi khóa phiên an toàn.

🔐 DES (mã hóa đối xứng): để mã hóa nội dung file.

✍️ Chữ ký số: đảm bảo xác thực người gửi.

🧾 Băm SHA-512: để kiểm tra tính toàn vẹn của dữ liệu.

📦 Cấu trúc dự án
Tập tin	Vai trò
client1.py	Client gửi file (mã hóa, ký, gửi)
client2.py	Client nhận file (xác thực, giải mã, lưu)
server1.py, server2.py	Server trung gian (chuyển tiếp gói tin)
legal_doc.txt	File gốc cần gửi đi
legal_doc_received.txt	File nhận được (đã giải mã)
server1_log.txt	Ghi log các gói tin đi qua Server1

⚙️ Cách hoạt động
Client2 tạo khóa RSA và gửi public key cho Client1.

Client1:

Sinh ra một session key ngẫu nhiên (dùng cho DES).

Mã hóa session key bằng public key nhận được từ client2.

Tạo chữ ký số từ hash SHA-512 của dữ liệu.

Mã hóa file bằng DES và gửi đi.

Client2:

Giải mã session key.

Xác minh chữ ký và kiểm tra hash.

Giải mã nội dung và lưu file.

✅ Tính năng nổi bật
🔐 Mã hóa kết hợp (RSA + DES)

✅ Xác thực file bằng chữ ký số

🔁 Mô phỏng môi trường truyền file không an toàn qua server trung gian

🧾 Kiểm tra tính toàn vẹn bằng SHA-512

📂 Ghi log đầy đủ quá trình gửi file

🚀 Cách chạy chương trình
Mỗi file chạy trong một cửa sổ terminal riêng:

bash
Copy
Edit
# Terminal 1
python server2.py

# Terminal 2
python server1.py

# Terminal 3
python client2.py
# Sau đó lần lượt chọn: 1 → 2 → 3 → 4

# Terminal 4
python client1.py
# Sau đó lần lượt chọn: 1 → 2 → 3 → 4
👤 Tác giả
Dự án được xây dựng phục vụ học tập môn Bảo mật thông tin, mô phỏng truyền file an toàn giữa hai đầu bằng Python, kết hợp mã hóa, xác thực, và kiểm tra toàn vẹn dữ liệu.
