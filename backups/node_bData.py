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
class Blockchain:
    """Blockchain implementation"""
    chain: List[Block] = field(default_factory=list)
    transaction_history: List[Transaction] = field(default_factory=list)

    def __post_init__(self):
        if not self.chain:
            self.chain.append(self._create_genesis_block())

    def _create_genesis_block(self) -> Block:
        """Create the first block in the chain"""
        timestamp = datetime.now().strftime("%Y-%m-%d %I:%M:%S")
        return Block(
            index=0,
            previous_hash="0",
            data_hash="0",
            data_content="Genesis Block",
            timestamp=timestamp,
            hash="0"
        )

    def add_block(self, block: Block) -> bool:
        """Add new block to the chain and record transaction"""
        if not self._is_valid_new_block(block):
            return False

        self.chain.append(block)
        self.transaction_history.append(
            Transaction(
                index=block.index,
                data_content=block.data_content,
                timestamp=block.timestamp
            )
        )
        return True

    def _is_valid_new_block(self, block: Block) -> bool:
        """Validate new block before adding to chain"""
        if not block.is_valid():
            logger.error("Invalid block hash")
            return False

        prev_block = self.chain[-1]
        if block.index != prev_block.index + 1:
            logger.error("Invalid block index")
            return False

        if block.previous_hash != prev_block.hash:
            logger.error("Invalid previous hash")
            return False

        return True

    def is_chain_valid(self) -> bool:
        """Verify integrity of entire blockchain"""
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            if not current.is_valid():
                return False
            if current.previous_hash != previous.hash:
                return False
        return True

class BlockchainServer:
    def __init__(self, config: ServerConfig):
        self.config = config
        self.blockchain = Blockchain()

    @staticmethod
    def calculate_data_hash(data: str) -> str:
        """Calculate SHA-512 hash of data"""
        return hashlib.sha512(data.encode()).hexdigest()

    def verify_block_data(self, block_info: Dict[str, Any]) -> Optional[Block]:
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

            # Verify data hash
            calculated_hash = self.calculate_data_hash(block.data_content)
            if calculated_hash != block.data_hash:
                logger.error("Data hash verification failed")
                return None

            return block

        except KeyError as e:
            logger.error(f"Missing required field in block data: {e}")
        except Exception as e:
            logger.error(f"Error processing block data: {e}")
        return None

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
                # Receive and process block data
                data = conn.recv(self.config.BUFFER_SIZE).decode()
                block_info = json.loads(data)
                logger.info(f"Received block: {block_info['index']}")

                # Verify and add block
                block = self.verify_block_data(block_info)
                if block and self.blockchain.add_block(block):
                    conn.sendall(b"CONFIRM")
                    logger.info("Block added successfully")
                else:
                    conn.sendall(b"ERROR")
                    logger.warning("Block verification failed")

                # Log chain status
                logger.info(f"Chain valid: {self.blockchain.is_chain_valid()}")
                self._log_transaction_history()

        except json.JSONDecodeError:
            logger.error("Invalid JSON data received")
            conn.sendall(b"ERROR")
        except Exception as e:
            logger.error(f"Error processing connection: {e}")
            conn.sendall(b"ERROR")

    def _log_transaction_history(self):
        """Log transaction history"""
        logger.info("\nTransaction History:")
        for tx in self.blockchain.transaction_history:
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

if __name__ == "__main__":
    main()
