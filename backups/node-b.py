import hashlib
import socket
import json
import os
from datetime import datetime
import sys
from typing import Optional, List
from dataclasses import dataclass
import logging

# ตั้งค่า logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('node_b.log'),
        logging.StreamHandler()
    ]
)

@dataclass
class Block:
    index: int
    previous_hash: str
    file_hash: str
    filename: str
    timestamp: str
    hash: str

    @staticmethod
    def calculate_hash(index: int, previous_hash: str, timestamp: str, file_hash: str, filename: str) -> str:
        """คำนวณค่า hash ของบล็อก"""
        block_content = f"{index}{previous_hash}{timestamp}{file_hash}{filename}".encode()
        return hashlib.sha512(block_content).hexdigest()

    def verify_hash(self) -> bool:
        """ตรวจสอบความถูกต้องของ hash"""
        calculated_hash = self.calculate_hash(
            self.index, self.previous_hash, self.timestamp,
            self.file_hash, self.filename
        )
        return calculated_hash == self.hash

class Blockchain:
    def __init__(self):
        self.chain: List[Block] = []
        self.create_genesis_block()

    def create_genesis_block(self) -> None:
        """สร้างบล็อกแรกในบล็อกเชน"""
        genesis_block = Block(
            index=0,
            previous_hash="0",
            file_hash="0",
            filename="Genesis Block",
            timestamp=datetime.now().strftime("%Y-%m-%d %I:%M %p"),
            hash="0"
        )
        self.chain.append(genesis_block)
        logging.info("Genesis block created")

    def add_block(self, block: Block) -> bool:
        """เพิ่มบล็อกใหม่ในเชน"""
        if not block.verify_hash():
            logging.error("Block hash verification failed")
            return False
            
        if block.previous_hash != self.chain[-1].hash:
            logging.error("Previous hash mismatch")
            return False
            
        self.chain.append(block)
        logging.info(f"New block added: {block}")
        return True

    def is_chain_valid(self) -> bool:
        """ตรวจสอบความถูกต้องของบล็อกเชน"""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            
            if not current_block.verify_hash():
                logging.error(f"Invalid hash in block {i}")
                return False
                
            if current_block.previous_hash != previous_block.hash:
                logging.error(f"Invalid chain link at block {i}")
                return False
        
        return True

def calculate_file_hash(filename: str) -> str:
    """คำนวณค่า SHA-512 ของไฟล์ที่รับมา"""
    sha512 = hashlib.sha512()
    try:
        with open(filename, "rb") as file:
            while chunk := file.read(8192):  # เพิ่มขนาด buffer เป็น 8KB
                sha512.update(chunk)
        return sha512.hexdigest()
    except Exception as e:
        logging.error(f"Error calculating file hash: {str(e)}")
        raise

def receive_file(conn: socket.socket, filename: str) -> Optional[str]:
    """รับไฟล์จาก Node A และคำนวณ hash"""
    try:
        with open(filename, "wb") as file:
            file_hash = hashlib.sha512()
            while True:
                data = conn.recv(8192)  # เพิ่มขนาด buffer เป็น 8KB
                if not data or data.endswith(b"<END>"):
                    # ตัด <END> ออกถ้ามี
                    if data.endswith(b"<END>"):
                        data = data[:-5]
                    if data:
                        file.write(data)
                        file_hash.update(data)
                    break
                file.write(data)
                file_hash.update(data)
        return file_hash.hexdigest()
    except Exception as e:
        logging.error(f"Error receiving file: {str(e)}")
        return None

def main():
    """ฟังก์ชันหลักสำหรับรันโปรแกรม"""
    port = 12345
    blockchain = Blockchain()
    
    # สร้างโฟลเดอร์สำหรับเก็บไฟล์ที่ได้รับ
    received_files_dir = "received_files"
    os.makedirs(received_files_dir, exist_ok=True)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('0.0.0.0', port))
            s.listen()
            logging.info(f"Listening on port {port}...")

            while True:
                try:
                    conn, addr = s.accept()
                    logging.info(f"Connected by {addr}")
                    
                    with conn:
                        # รับข้อมูลบล็อก
                        block_data = conn.recv(1024).decode()
                        block_info = json.loads(block_data)
                        
                        # ส่ง ACK กลับไป
                        conn.sendall(b"ACK")
                        
                        # สร้างชื่อไฟล์ใหม่
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        new_filename = os.path.join(
                            received_files_dir,
                            f"{timestamp}_{os.path.basename(block_info['filename'])}"
                        )
                        
                        # รับไฟล์และคำนวณ hash
                        received_hash = receive_file(conn, new_filename)
                        
                        if received_hash and received_hash == block_info["file_hash"]:
                            # สร้างบล็อกใหม่
                            new_block = Block(
                                index=block_info['index'],
                                previous_hash=block_info['previous_hash'],
                                file_hash=block_info['file_hash'],
                                filename=block_info['filename'],
                                timestamp=block_info['timestamp'],
                                hash=block_info['hash']
                            )
                            
                            # เพิ่มบล็อกในบล็อกเชน
                            if blockchain.add_block(new_block):
                                logging.info(f"File received and saved as {new_filename}")
                                logging.info("Block added to blockchain successfully")
                                conn.sendall(b"CONFIRM")
                            else:
                                logging.error("Failed to add block to blockchain")
                                conn.sendall(b"ERROR")
                        else:
                            logging.error("File hash verification failed")
                            conn.sendall(b"ERROR")
                            # ลบไฟล์ที่ไม่ถูกต้อง
                            if os.path.exists(new_filename):
                                os.remove(new_filename)
                                logging.info(f"Invalid file removed: {new_filename}")
                except Exception as e:
                    logging.error(f"Error during connection handling: {str(e)}")
    except KeyboardInterrupt:
        logging.info("Server stopped by user")
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()

