import hashlib
import socket
import json
from datetime import datetime
import os
import sys
from typing import Optional

class Block:
    def __init__(self, index: int, previous_hash: str, file_hash: str, filename: str, timestamp: Optional[str] = None):
        self.index = index
        self.previous_hash = previous_hash
        self.file_hash = file_hash
        self.filename = filename
        self.timestamp = timestamp or datetime.now().strftime("%Y-%m-%d %I:%M %p")
        self.hash = self.calculate_hash()

    def calculate_hash(self) -> str:
        """สร้างค่าแฮช SHA-512 สำหรับเนื้อหาของบล็อก"""
        block_content = f"{self.index}{self.previous_hash}{self.timestamp}{self.file_hash}{self.filename}".encode()
        return hashlib.sha512(block_content).hexdigest()

    def to_dict(self) -> dict:
        """แปลงข้อมูลบล็อกเป็น dictionary"""
        return {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "file_hash": self.file_hash,
            "filename": self.filename,
            "hash": self.hash
        }

def calculate_file_hash(filename: str) -> str:
    """คำนวณค่า SHA-512 ของไฟล์"""
    sha512 = hashlib.sha512()
    try:
        with open(filename, "rb") as file:
            while chunk := file.read(8192):  # เพิ่มขนาด buffer เป็น 8KB
                sha512.update(chunk)
        return sha512.hexdigest()
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        sys.exit(1)
    except PermissionError:
        print(f"Error: Permission denied when accessing '{filename}'.")
        sys.exit(1)
    except Exception as e:
        print(f"Error calculating file hash: {str(e)}")
        sys.exit(1)

def validate_file_type(filename: str) -> bool:
    """ตรวจสอบนามสกุลไฟล์ที่อนุญาต"""
    allowed_extensions = {'.pdf', '.jpg', '.jpeg', '.png'}
    return os.path.splitext(filename)[1].lower() in allowed_extensions

def send_file_and_block(filename: str, server_ip: str, server_port: int) -> None:
    if not validate_file_type(filename):
        print("Error: Invalid file type. Only PDF, JPG, and PNG files are allowed.")
        return

    try:
        # คำนวณค่าแฮชของไฟล์
        file_hash = calculate_file_hash(filename)
        
        # สร้างบล็อกข้อมูลไฟล์
        new_block = Block(index=1, previous_hash="0", file_hash=file_hash, filename=os.path.basename(filename))

        # สร้าง socket และเชื่อมต่อกับ Node B
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(30)  # ตั้งค่า timeout 30 วินาที
            try:
                s.connect((server_ip, server_port))
                print(f"Connected to Node B at {server_ip}:{server_port}")
                
                # ส่งข้อมูลบล็อกในรูปแบบ JSON
                block_data = json.dumps(new_block.to_dict())
                s.sendall(block_data.encode())
                
                # รอรับ ACK จาก Node B
                response = s.recv(1024).decode()
                if response != "ACK":
                    print("Error: Did not receive acknowledgment from Node B")
                    return
                
                # ส่งไฟล์
                file_size = os.path.getsize(filename)
                bytes_sent = 0
                with open(filename, "rb") as file:
                    while True:
                        file_data = file.read(8192)  # เพิ่มขนาด buffer เป็น 8KB
                        if not file_data:
                            break
                        s.sendall(file_data)
                        bytes_sent += len(file_data)
                        # แสดงความคืบหน้า
                        progress = (bytes_sent / file_size) * 100
                        print(f"\rSending file... {progress:.1f}%", end="")
                
                s.sendall(b"<END>")
                print("\nFile sent successfully.")

                # รอรับการยืนยันจาก Node B
                confirmation = s.recv(1024).decode()
                if confirmation == "CONFIRM":
                    print("Node B confirmed that the data is correct and intact.")
                else:
                    print("Warning: Node B reported an error in data verification.")

            except socket.timeout:
                print("Error: Connection timed out")
            except ConnectionRefusedError:
                print(f"Error: Connection refused to {server_ip}:{server_port}")
            except Exception as e:
                print(f"Error during file transfer: {str(e)}")

    except Exception as e:
        print(f"Error: {str(e)}")

def main():
    """ฟังก์ชันหลักสำหรับรันโปรแกรม"""
    try:
        while True:
            filename = input("\nPlease enter the file path (PDF, JPG, PNG) to send (or 'quit' to exit): ").strip()
            if filename.lower() == 'quit':
                break
                
            # ตรวจสอบว่าไฟล์มีอยู่จริง
            if not os.path.exists(filename):
                print(f"Error: File '{filename}' does not exist.")
                continue
                
            server_ip = input("Enter Node B's IP address [default: 192.168.1.107]: ").strip() or '192.168.1.107'
            server_port = input("Enter Node B's port [default: 12345]: ").strip() or '12345'
            
            try:
                server_port = int(server_port)
            except ValueError:
                print("Error: Port must be a number")
                continue
                
            if not (1024 <= server_port <= 65535):
                print("Error: Port must be between 1024 and 65535")
                continue
                
            send_file_and_block(filename, server_ip, server_port)
            
    except KeyboardInterrupt:
        print("\nProgram terminated by user.")
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")

if __name__ == "__main__":
    main()
