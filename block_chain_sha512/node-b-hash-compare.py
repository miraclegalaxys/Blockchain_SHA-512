import hashlib
import socket
import json
import logging
from datetime import datetime
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class ServerConfig:
    """Configuration for server"""
    HOST: str = '0.0.0.0'
    PORT: int = 12345
    BUFFER_SIZE: int = 4096

@dataclass
class Transaction:
    """Transaction record structure"""
    index: int
    data_content: str
    timestamp: str

@dataclass
class Block:
    """Block structure for blockchain"""
    index: int
    previous_hash: str
    data_hash: str
    data_content: str
    timestamp: str
    hash: str

    def is_valid(self) -> bool:
        """Verify block hash"""
        calculated_hash = self.calculate_hash()
        return calculated_hash == self.hash

    def calculate_hash(self) -> str:
        """Calculate block hash"""
        block_content = (
            f"{self.index}{self.previous_hash}"
            f"{self.timestamp}{self.data_hash}{self.data_content}"
        ).encode()
        return hashlib.sha512(block_content).hexdigest()

@dataclass
class HashComparison:
    """Structure for hash comparison results"""
    received_data_hash: str
    calculated_data_hash: str
    received_block_hash: str
    calculated_block_hash: str
    is_data_hash_match: bool
    is_block_hash_match: bool

class BlockchainServer:
    def __init__(self, config: ServerConfig):
        self.config = config
        self.blockchain = []
        self.transaction_history = []

    @staticmethod
    def calculate_data_hash(data: str) -> str:
        """Calculate SHA-512 hash of data"""
        return hashlib.sha512(data.encode()).hexdigest()

    def verify_block_data(self, block_info: Dict[str, Any]) -> tuple[Optional[Block], HashComparison]:
        """Verify received block data and create Block instance"""
        try:
            # Create Block instance
            block = Block(
                index=block_info['index'],
                previous_hash=block_info['previous_hash'],
                data_hash=block_info['data_hash'],
                data_content=block_info['data_content'],
                timestamp=block_info['timestamp'],
                hash=block_info['hash']
            )

            # Calculate hashes for comparison
            calculated_data_hash = self.calculate_data_hash(block.data_content)
            calculated_block_hash = block.calculate_hash()

            # Create hash comparison results
            hash_comparison = HashComparison(
                received_data_hash=block.data_hash,
                calculated_data_hash=calculated_data_hash,
                received_block_hash=block.hash,
                calculated_block_hash=calculated_block_hash,
                is_data_hash_match=calculated_data_hash == block.data_hash,
                is_block_hash_match=calculated_block_hash == block.hash
            )

            return block, hash_comparison

        except KeyError as e:
            logger.error(f"Missing required field in block data: {e}")
        except Exception as e:
            logger.error(f"Error processing block data: {e}")
        return None, None

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

    def start(self):
        """Start blockchain server"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.config.HOST, self.config.PORT))
            s.listen()
            logger.info(f"Server listening on port {self.config.PORT}")

            while True:
                try:
                    conn, addr = s.accept()
                    logger.info(f"Connected by {addr}")
                    self._handle_connection(conn)
                except KeyboardInterrupt:
                    logger.info("Server shutdown requested")
                    break
                except Exception as e:
                    logger.error(f"Error handling connection: {e}")

    def _handle_connection(self, conn: socket.socket):
        """Handle incoming connection"""
        try:
            with conn:
                # Receive block data
                data = conn.recv(self.config.BUFFER_SIZE).decode()
                block_info = json.loads(data)
                logger.info(f"\nReceived block: {block_info['index']}")
                logger.info("Block Content:")
                logger.info(f"├─ Data Content: {block_info['data_content']}")
                logger.info(f"├─ Timestamp: {block_info['timestamp']}")
                logger.info(f"└─ Previous Hash: {block_info['previous_hash']}\n")

                # Verify block data and get hash comparison
                block, hash_comparison = self.verify_block_data(block_info)
                
                if block and hash_comparison:
                    # Print hash comparison
                    self.print_hash_comparison(hash_comparison)
                    
                    # Verify if all hashes match
                    if hash_comparison.is_data_hash_match and hash_comparison.is_block_hash_match:
                        self.blockchain.append(block)
                        self.transaction_history.append(
                            Transaction(
                                index=block.index,
                                data_content=block.data_content,
                                timestamp=block.timestamp
                            )
                        )
                        conn.sendall(b"CONFIRM")
                        logger.info("\nBlock verification successful and added to blockchain")
                    else:
                        conn.sendall(b"ERROR")
                        logger.warning("\nBlock verification failed - hash mismatch")
                else:
                    conn.sendall(b"ERROR")
                    logger.warning("\nBlock verification failed - invalid data")

                self._log_transaction_history()

        except json.JSONDecodeError:
            logger.error("Invalid JSON data received")
            conn.sendall(b"ERROR")
        except Exception as e:
            logger.error(f"Error processing connection: {e}")
            conn.sendall(b"ERROR")

    def _log_transaction_history(self):
        """Log transaction history"""
        if self.transaction_history:
            logger.info("\n=== Transaction History ===")
            for tx in self.transaction_history:
                logger.info(
                    f"Index: {tx.index}, "
                    f"Data: {tx.data_content}, "
                    f"Time: {tx.timestamp}"
                )

def main():
    try:
        config = ServerConfig()
        server = BlockchainServer(config)
        server.start()
    except Exception as e:
        logger.error(f"Server error: {e}")

main()
