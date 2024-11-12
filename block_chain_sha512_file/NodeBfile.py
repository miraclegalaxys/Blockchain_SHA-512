import hashlib
import socket
import json
import os
from datetime import datetime
import logging
from dataclasses import dataclass

# Set up logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

@dataclass
class HashComparison:
    received_data_hash: str
    calculated_data_hash: str
    is_data_hash_match: bool
    received_block_hash: str
    calculated_block_hash: str
    is_block_hash_match: bool

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
        return Block(0, "0", "0", "Genesis Block", datetime.now().strftime("%Y-%m-%d %I:%M %p"), "0")

    def add_block(self, block):
        self.chain.append(block)
        return self.is_chain_valid()

    def is_chain_valid(self):
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
        block_content = f"{block.index}{block.previous_hash}{block.timestamp}{block.file_hash}{block.filename}".encode()
        return hashlib.sha512(block_content).hexdigest()

    def print_hash_comparison(self, comparison: HashComparison):
        """Print detailed hash comparison"""
        logger.info("\n=== Hash Comparison ===")
        logger.info("Data Hash Comparison:")
        logger.info(f"├─ Received from Node A  : {comparison.received_data_hash}")
        logger.info(f"├─ Calculated by Node B  : {comparison.calculated_data_hash}")
        logger.info(f"└─ Match                 : {'✓' if comparison.is_data_hash_match else '✗'}")
        
        logger.info("\nBlock Hash Comparison:")
        logger.info(f"├─ Received from Node A  : {comparison.received_block_hash}")
        logger.info(f"├─ Calculated by Node B  : {comparison.calculated_block_hash}")
        logger.info(f"└─ Match                 : {'✓' if comparison.is_block_hash_match else '✗'}")

def calculate_file_hash(filename):
    sha512 = hashlib.sha512()
    with open(filename, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha512.update(chunk)
    return sha512.hexdigest()

def receive_data(port=12345):
    blockchain = Blockchain()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('0.0.0.0', port))
        s.listen()
        print("Node B waiting for connection...")
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            
            # Receive block data
            block_data = conn.recv(1024).decode()
            block_info = json.loads(block_data)
            conn.sendall(b"ACK")

            # Generate a new filename to store the received file
            new_filename = f"received_{os.path.basename(block_info['filename'])}"
            with open(new_filename, "wb") as file:
                while True:
                    file_data = conn.recv(4096)
                    if file_data == b"<END>":
                        break
                    file.write(file_data)
            print(f"File received successfully and saved as {new_filename}.")

            # Verify the file hash
            received_file_hash = calculate_file_hash(new_filename)
            calculated_block_hash = Blockchain.calculate_hash(Block(
                index=block_info['index'],
                previous_hash=block_info['previous_hash'],
                file_hash=block_info['file_hash'],
                filename=block_info['filename'],
                timestamp=block_info['timestamp'],
                block_hash=block_info['hash']
            ))

            # Create HashComparison instance
            comparison = HashComparison(
                received_data_hash=block_info["file_hash"],
                calculated_data_hash=received_file_hash,
                is_data_hash_match=(received_file_hash == block_info["file_hash"]),
                received_block_hash=block_info["hash"],
                calculated_block_hash=calculated_block_hash,
                is_block_hash_match=(block_info["hash"] == calculated_block_hash)
            )

            # Print the hash comparison
            blockchain.print_hash_comparison(comparison)

            # Add block if data matches and confirm back to Node A
            if comparison.is_data_hash_match and comparison.is_block_hash_match:
                new_block = Block(
                    index=block_info['index'],
                    previous_hash=block_info['previous_hash'],
                    file_hash=block_info['file_hash'],
                    filename=block_info['filename'],
                    timestamp=block_info['timestamp'],
                    block_hash=block_info['hash']
                )
                if blockchain.add_block(new_block):
                    conn.sendall(b"CONFIRM")
                    print("Block added to blockchain.")
                else:
                    conn.sendall(b"ERROR")
            else:
                conn.sendall(b"ERROR")
                print("Hash comparison failed. Block is invalid.")

    # Final check of blockchain integrity
    print("\nBlockchain Integrity Check:", "Valid" if blockchain.is_chain_valid() else "Invalid")

# Start Node B
receive_data()
