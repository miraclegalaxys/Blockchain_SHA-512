import hashlib
import socket
import json
from datetime import datetime

class Block:
    def __init__(self, index, previous_hash, data_hash, data_content, timestamp=None):
        self.index = index
        self.previous_hash = previous_hash
        self.data_hash = data_hash
        self.data_content = data_content
        self.timestamp = timestamp or datetime.now().strftime("%Y-%m-%d %I:%M %p")
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        """สร้างค่าแฮช SHA-512 สำหรับเนื้อหาของบล็อก"""
        block_content = f"{self.index}{self.previous_hash}{self.timestamp}{self.data_hash}{self.data_content}".encode()
        return hashlib.sha512(block_content).hexdigest()

def calculate_data_hash(data):
    """คำนวณค่า SHA-512 ของข้อมูล"""
    return hashlib.sha512(data.encode()).hexdigest()

def send_data_and_block(data_content, server_ip, server_port):
    previous_hash = "0"  # ค่า previous hash ของบล็อกแรก
    index = 1  # บล็อกแรก
    
    # คำนวณค่าแฮชของข้อมูล
    data_hash = calculate_data_hash(data_content) + " modified" #กรณีนี้เมื่อ Hash ไม่ตรงกัน
    
    print(f"Calculated data hash (to be sent): {data_hash}")
    
    # สร้างบล็อกข้อมูล
    new_block = Block(index=index, previous_hash=previous_hash, data_hash=data_hash, data_content=data_content)

    try:
        # สร้าง socket และเชื่อมต่อกับ Node B
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((server_ip, server_port))
            print("Connected to Node B")
            
            # ส่งข้อมูลบล็อกในรูปแบบ JSON
            block_data = json.dumps({
                "index": new_block.index,
                "previous_hash": new_block.previous_hash,
                "timestamp": new_block.timestamp,
                "data_hash": new_block.data_hash,
                "data_content": new_block.data_content,
                "hash": new_block.hash
            })
            s.sendall(block_data.encode())
            
            # รอรับการยืนยันจาก Node B
            confirmation = s.recv(1024).decode()
            if confirmation == "CONFIRM":
                print("Node B confirmed that the data is correct and intact.")
            else:
                print("Node B did not confirm the data.")

    except Exception as e:
        print(f"An error occurred: {e}")

# ใช้ส่งข้อมูล DATA
data_content = input("Please enter the data content to send: ")
server_ip = '192.168.1.107'  # IP ของ Node B
server_port = 12345      # พอร์ตของ Node B

send_data_and_block(data_content, server_ip, server_port)
