import hashlib
import socket
import json
import logging
from datetime import datetime
from typing import Optional, Dict, Any
from dataclasses import dataclass

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class BlockConfig:
    """Configuration for network connection"""
    SERVER_IP: str = '192.168.1.107'
    SERVER_PORT: int = 12345
    BUFFER_SIZE: int = 4096
    TIMEOUT: int = 30

@dataclass
class Block:
    """Block structure for blockchain"""
    index: int
    previous_hash: str
    data_hash: str
    data_content: str
    timestamp: Optional[str] = None
    
    def __post_init__(self):
        self.timestamp = self.timestamp or datetime.now().strftime("%Y-%m-%d %I:%M:%S")
        self.hash = self.calculate_hash()
    
    def calculate_hash(self) -> str:
        """Calculate SHA-512 hash for block content"""
        block_content = (
            f"{self.index}{self.previous_hash}"
            f"{self.timestamp}{self.data_hash}{self.data_content}"
        ).encode()
        return hashlib.sha512(block_content).hexdigest()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert block to dictionary for JSON serialization"""
        return {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "data_hash": self.data_hash,
            "data_content": self.data_content,
            "hash": self.hash
        }

class BlockchainClient:
    def __init__(self, config: BlockConfig):
        self.config = config
    
    @staticmethod
    def calculate_data_hash(data: str) -> str:
        """Calculate SHA-512 hash of input data"""
        return hashlib.sha512(data.encode()).hexdigest()
    
    def send_block(self, block: Block) -> bool:
        """Send block to Node B and wait for confirmation"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.config.TIMEOUT)
                s.connect((self.config.SERVER_IP, self.config.SERVER_PORT))
                logger.info("Connected to Node B")
                
                # Send block data
                block_data = json.dumps(block.to_dict())
                s.sendall(block_data.encode())
                logger.info(f"Sent block with hash: {block.hash}")
                
                # Wait for confirmation
                confirmation = s.recv(self.config.BUFFER_SIZE).decode()
                if confirmation == "CONFIRM":
                    logger.info("Node B confirmed data integrity")
                    return True
                else:
                    logger.warning(f"Node B response: {confirmation}")
                    return False
                    
        except socket.timeout:
            logger.error("Connection timed out")
        except ConnectionRefusedError:
            logger.error("Connection refused - Node B might be offline")
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
        return False

def main():
    try:
        config = BlockConfig()
        client = BlockchainClient(config)
        
        # Get data from user
        data_content = input("Enter data content to send: ").strip()
        if not data_content:
            logger.error("Data content cannot be empty")
            return
        
        # Calculate data hash
        data_hash = client.calculate_data_hash(data_content) + "EDIT"
        logger.info(f"Calculated data hash: {data_hash}")
        
        # Create new block
        block = Block(
            index=1,
            previous_hash="0",
            data_hash=data_hash,
            data_content=data_content
        )
        
        # Send block
        if client.send_block(block):
            logger.info("Transaction completed successfully")
        else:
            logger.error("Transaction failed")
            
    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
    except Exception as e:
        logger.error(f"Unexpected error in main: {str(e)}")

main()
