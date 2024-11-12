import socket

def receive_data():
    # ตั้งค่า IP และ Port
    server_ip = '127.0.0.1'
    server_port = 12345

    # สร้าง socket และเริ่มฟัง
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((server_ip, server_port))
        s.listen()
        print(f"Waiting for connection on {server_ip}:{server_port}...")
        conn, addr = s.accept()

        with conn:
            print(f"Connected by {addr}")
            # รับข้อมูลจาก Node A
            data = conn.recv(1024).decode()
            print(f"Received data: {data}")

            # ส่งข้อความตอบกลับไปยัง Node A
            response = f"Data received: {data}"
            conn.sendall(response.encode())

receive_data()
