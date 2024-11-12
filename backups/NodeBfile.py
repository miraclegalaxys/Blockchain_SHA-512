import hashlib
import socket
import json
import os
from datetime import datetime

class Block:
    def __init__(self, index, previous_hash, file_hash, filename, timestamp, block_hash):
        self.index = index
        self.previous_hash = previous_hash
        self.file_hash = file_hash
        self.filename = filename
        self.timestamp = timestamp
        self.hash = block_hash

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        """สร้างบล็อกแรกในบล็อกเชน"""
        return Block(0, "0", "0", "Genesis Block", datetime.now().strftime("%Y-%m-%d %I:%M %p"), "0")

    def add_block(self, block):
        """เพิ่มบล็อกใหม่ในเชน"""
        self.chain.append(block)

    def is_chain_valid(self):
        """ตรวจสอบความถูกต้องของบล็อกเชน"""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            if current_block.previous_hash != previous_block.hash:
                return False
            if current_block.hash != self.calculate_hash(current_block):
                return False
        return True

    @staticmethod
    def calculate_hash(block):
        """คำนวณค่า hash ของบล็อก"""
        block_content = f"{block.index}{block.previous_hash}{block.timestamp}{block.file_hash}{block.filename}".encode()
        return hashlib.sha512(block_content).hexdigest()

def calculate_file_hash(filename):
    """คำนวณค่า SHA-512 ของไฟล์ที่รับมา"""
    sha512 = hashlib.sha512()
    with open(filename, "rb") as file:
        while chunk := file.read(1024):
            sha512.update(chunk)
    return sha512.hexdigest()

# เริ่มการรับข้อมูล
port = 12345
blockchain = Blockchain()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind(('0.0.0.0', port))
    s.listen()
    print("Waiting for connection from Node A...")
    conn, addr = s.accept()
    with conn:
        print(f"Connected by {addr}")
        
        # รับข้อมูลบล็อก
        block_data = conn.recv(1024).decode()
        block_info = json.loads(block_data)
        conn.sendall(b"ACK")  # ส่ง ACK กลับไปยัง Node A เพื่อเริ่มรับข้อมูลไฟล์
        
        # สร้างชื่อไฟล์ใหม่เพื่อเก็บข้อมูลที่รับ
        new_filename = f"received_{os.path.basename(block_info['filename'])}"
        with open(new_filename, "wb") as file:
            while True:
                file_data = conn.recv(1024)
                if not file_data:
                    break
                file.write(file_data)
        print(f"File received successfully and saved as {new_filename}.")

        # ตรวจสอบความถูกต้องของไฟล์
        received_file_hash = calculate_file_hash(new_filename)
        if received_file_hash == block_info["file_hash"]:
            # สร้างบล็อกใหม่และเพิ่มในบล็อกเชน
            new_block = Block(
                index=block_info['index'],
                previous_hash=block_info['previous_hash'],
                file_hash=block_info['file_hash'],
                filename=block_info['filename'],
                timestamp=block_info['timestamp'],
                block_hash=block_info['hash']
            )
            blockchain.add_block(new_block)
            print("File hash matches, block added to blockchain.")

            # ส่งข้อความยืนยันกลับไปให้ Node A
            conn.sendall(b"CONFIRM")
        else:
            print("File hash does not match. Block is invalid.")
            conn.sendall(b"ERROR")  # ส่งข้อความ ERROR กลับไปหากข้อมูลไม่ตรงกัน

# ตรวจสอบความสมบูรณ์ของบล็อกเชน
print("\nBlockchain Integrity Check:", "Valid" if blockchain.is_chain_valid() else "Invalid")
