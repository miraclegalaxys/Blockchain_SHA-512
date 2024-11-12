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
        """Calculate SHA-512 hash of the block content."""
        block_content = f"{self.index}{self.previous_hash}{self.timestamp}{self.file_hash}{self.filename}".encode()
        return hashlib.sha512(block_content).hexdigest()

def calculate_file_hash(filename):
    """Calculate SHA-512 hash of a file."""
    sha512 = hashlib.sha512()
    with open(filename, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha512.update(chunk)
    return sha512.hexdigest()

def send_file_and_block(filename, server_ip, server_port):
    try:
        file_hash = calculate_file_hash(filename)
        new_block = Block(index=1, previous_hash="0", file_hash=file_hash, filename=filename)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((server_ip, server_port))
            block_data = json.dumps({
                "index": new_block.index,
                "previous_hash": new_block.previous_hash,
                "timestamp": new_block.timestamp,
                "file_hash": new_block.file_hash,
                "filename": new_block.filename,
                "hash": new_block.hash
            })
            s.sendall(block_data.encode())
            s.recv(1024)

            with open(filename, "rb") as file:
                while chunk := file.read(4096):
                    s.sendall(chunk)
            s.sendall(b"<END>")

            confirmation = s.recv(1024).decode()
            print("Node B confirmation:", confirmation)
    except FileNotFoundError:
        print("File not found. Please check the filename and try again.")
    except Exception as e:
        print(f"Error: {e}")

# Send a file
filename = input("Enter file path to send: ")
send_file_and_block(filename, '192.168.1.107', 12345)

