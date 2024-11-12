import hashlib
import socket
import json
from datetime import datetime
import os

class Block:
    def __init__(self, index, previous_hash, file_hash, filename, timestamp=None):
        self.index = index
        self.previous_hash = previous_hash
        self.file_hash = file_hash
        self.filename = filename
        self.timestamp = timestamp or datetime.now().strftime("%Y-%m-%d %I:%M %p")
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        """สร้างค่าแฮช SHA-512 สำหรับเนื้อหาของบล็อก"""
        block_content = f"{self.index}{self.previous_hash}{self.timestamp}{self.file_hash}{self.filename}".encode()
        return hashlib.sha512(block_content).hexdigest()

def calculate_file_hash(filename):
    """คำนวณค่า SHA-512 ของไฟล์"""
    sha512 = hashlib.sha512()
    with open(filename, "rb") as file:
        while chunk := file.read(1024):
            sha512.update(chunk)
    return sha512.hexdigest()

def send_file_and_block(filename, server_ip, server_port):
    previous_hash = "0"  # ค่า previous hash ของบล็อกแรก
    index = 1  # บล็อกแรก
    
    # คำนวณค่าแฮชของไฟล์
    file_hash = calculate_file_hash(filename)
    
    # สร้างบล็อกข้อมูลไฟล์
    new_block = Block(index=index, previous_hash=previous_hash, file_hash=file_hash, filename=filename)

    # สร้าง socket และเชื่อมต่อกับ Node B
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_ip, server_port))
        print("Connected to Node B")
        
        # ส่งข้อมูลบล็อกในรูปแบบ JSON
        block_data = json.dumps({
            "index": new_block.index,
            "previous_hash": new_block.previous_hash,
            "timestamp": new_block.timestamp,
            "file_hash": new_block.file_hash,
            "filename": new_block.filename,
            "hash": new_block.hash
        })
        s.sendall(block_data.encode())
        s.recv(1024)  # รอ ACK จาก Node B เพื่อเริ่มส่งไฟล์
        
        # ส่งไฟล์
        with open(filename, "rb") as file:
            file_data = file.read(1024)
            while file_data:
                s.sendall(file_data)
                file_data = file.read(1024)
        
        s.sendall(b"<END>")
        print("File sent successfully.")

        # รอรับการยืนยันจาก Node B
        confirmation = s.recv(1024).decode()
        if confirmation == "CONFIRM":
            print("Node B confirmed that the data is correct and intact.")
        else:
            print("Node B did not confirm the data.")

# ใช้ส่งไฟล์
filename = input("Please enter the file path (PDF, JPG, PNG) to send: ")
server_ip = '192.168.1.107'  # IP ของ Node B
server_port = 12345      # พอร์ตของ Node B

send_file_and_block(filename, server_ip, server_port)

