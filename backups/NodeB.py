import hashlib
import socket
import json
from datetime import datetime

class Block:
    def __init__(self, index, previous_hash, data_hash, data_content, timestamp, block_hash):
        self.index = index
        self.previous_hash = previous_hash
        self.data_hash = data_hash
        self.data_content = data_content
        self.timestamp = timestamp
        self.hash = block_hash

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.transaction_history = []  # บันทึกประวัติการทำธุรกรรม

    def create_genesis_block(self):
        """สร้างบล็อกแรกในบล็อกเชน"""
        return Block(0, "0", "0", "Genesis Block", datetime.now().strftime("%Y-%m-%d %I:%M %p"), "0")

    def add_block(self, block):
        """เพิ่มบล็อกใหม่ในเชนและบันทึกประวัติการทำธุรกรรม"""
        self.chain.append(block)
        self.transaction_history.append({
            "index": block.index,
            "data_content": block.data_content,
            "timestamp": block.timestamp
        })

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
        block_content = f"{block.index}{block.previous_hash}{block.timestamp}{block.data_hash}{block.data_content}".encode()
        return hashlib.sha512(block_content).hexdigest()

def calculate_data_hash(data):
    """คำนวณค่า SHA-512 ของข้อมูลที่รับมา"""
    return hashlib.sha512(data.encode()).hexdigest()

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
        
        try:
            # รับข้อมูลบล็อก
            block_data = conn.recv(1024).decode()
            block_info = json.loads(block_data)
            
            # แสดงข้อมูลบล็อกที่ได้รับ
            print("Received block data:")
            print(f"Index: {block_info['index']}")
            print(f"Previous Hash: {block_info['previous_hash']}")
            print(f"Timestamp: {block_info['timestamp']}")
            print(f"Data Content: {block_info['data_content']}")
            print(f"Hash: {block_info['hash']}")
            
            # ตรวจสอบความถูกต้องของข้อมูลที่รับ
            received_data_hash = calculate_data_hash(block_info["data_content"])
            if received_data_hash == block_info["data_hash"]:
                # สร้างบล็อกใหม่และเพิ่มในบล็อกเชน
                new_block = Block(
                    index=block_info['index'],
                    previous_hash=block_info['previous_hash'],
                    data_hash=block_info['data_hash'],
                    data_content=block_info['data_content'],
                    timestamp=block_info['timestamp'],
                    block_hash=block_info['hash']
                )
                blockchain.add_block(new_block)
                print("Data hash matches, block added to blockchain.")

                # ส่งข้อความยืนยันกลับไปให้ Node A
                conn.sendall(b"CONFIRM")
            else:
                print("Data hash does not match. Block is invalid.")
                conn.sendall(b"ERROR")  # ส่งข้อความ ERROR กลับไปหากข้อมูลไม่ตรงกัน
            
            # ตรวจสอบความสมบูรณ์ของบล็อกเชน
            print("\nBlockchain Integrity Check:", "Valid" if blockchain.is_chain_valid() else "Invalid")

        except Exception as e:
            print(f"An error occurred during processing: {e}")

        # แสดงประวัติการทำธุรกรรมทั้งหมด
        print("\nTransaction History:")
        for tx in blockchain.transaction_history:
            print(f"Transaction Index: {tx['index']}, Data: {tx['data_content']}, Timestamp: {tx['timestamp']}")
