import hashlib
import time

class Block:
    def __init__(self, index, previous_hash, data, timestamp=None):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp or time.time()
        self.data = data
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        """Calculate SHA-512 hash of the block's contents."""
        block_content = f"{self.index}{self.previous_hash}{self.timestamp}{self.data}".encode()
        return hashlib.sha512(block_content).hexdigest()

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        """Create the first block in the blockchain."""
        return Block(0, "0", "Genesis Block")

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, new_data):
        latest_block = self.get_latest_block()
        new_block = Block(
            index=latest_block.index + 1,
            previous_hash=latest_block.hash,
            data=new_data
        )
        self.chain.append(new_block)

    def is_chain_valid(self):
        """Check if the blockchain is valid by verifying each block's hash."""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            if current_block.hash != current_block.calculate_hash():
                return False
            if current_block.previous_hash != previous_block.hash:
                return False
        return True

# Create blockchain and add transactions
blockchain = Blockchain()
blockchain.add_block("Transaction 1: User A to User B")
blockchain.add_block("Transaction 2: User B to User C")
blockchain.add_block("Transaction 3: User C to User D")

# Display the blockchain
for block in blockchain.chain:
    print(f"Block {block.index}:")
    print(f"    Previous Hash: {block.previous_hash}")
    print(f"    Data: {block.data}")
    print(f"    Hash: {block.hash}")
    print(f"    Timestamp: {block.timestamp}\n")

# Verify the integrity of the blockchain
print("Is blockchain valid?", blockchain.is_chain_valid())
