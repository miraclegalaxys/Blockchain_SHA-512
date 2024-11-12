import socket

def send_data():
    # ข้อมูลที่ต้องการส่ง
    data_content = input("Enter the data to send: ") 
    data_content = data_content + " I edit"  # เพิ่มข้อความ "I edit" เข้าไปในข้อมูล

    # สร้าง socket และเชื่อมต่อกับ Node B
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        server_ip = '192.168.1.107'  # IP ของ Node B
        server_port = 12345      # พอร์ตของ Node B
        s.connect((server_ip, server_port))

        # ส่งข้อมูลไปยัง Node B
        s.sendall(data_content.encode('utf-8'))

        # รอรับข้อความตอบกลับจาก Node B
        response = s.recv(1024).decode()
        print(f"Received from Node B: {response}")

send_data()
