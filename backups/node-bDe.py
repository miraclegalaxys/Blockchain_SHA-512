import socket
import sys
from typing import Tuple
from datetime import datetime

# Configuration constants
CONFIG = {
    'SERVER_IP': '127.0.0.1',
    'SERVER_PORT': 12345,
    'BUFFER_SIZE': 1024,
    'ENCODING': 'utf-8',
    'BACKLOG': 5  # Maximum number of queued connections
}

class NodeB:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.socket = None

    def setup_server(self) -> Tuple[socket.socket, bool]:
        """Setup server socket with error handling"""
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            return server_socket, True
        except socket.error as e:
            print(f"Error setting up server: {str(e)}")
            return None, False
        
    def log_message(self, message: str):
        """Log message with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {message}")

    def handle_client(self, client_socket: socket.socket, client_address: Tuple[str, int]):
        """Handle individual client connection"""
        try:
            # Receive data from client
            data = client_socket.recv(CONFIG['BUFFER_SIZE']).decode(CONFIG['ENCODING'])
            
            if not data:
                self.log_message("No data received from client")
                return

            self.log_message(f"Received data from {client_address}: {data}")

            # Process and send response
            response = f"Data received: {data}"
            client_socket.sendall(response.encode(CONFIG['ENCODING']))
            self.log_message(f"Response sent to {client_address}")

        except Exception as e:
            self.log_message(f"Error handling client {client_address}: {str(e)}")
        finally:
            client_socket.close()

    def start_server(self):
        """Start server and listen for connections"""
        server_socket, success = self.setup_server()
        if not success:
            sys.exit(1)

        try:
            with server_socket:
                server_socket.listen(CONFIG['BACKLOG'])
                self.log_message(f"Server listening on {self.host}:{self.port}")

                while True:
                    try:
                        # Accept client connection
                        client_socket, client_address = server_socket.accept()
                        self.log_message(f"New connection from {client_address}")
                        
                        # Handle client in the same thread (synchronous)
                        with client_socket:
                            self.handle_client(client_socket, client_address)
                            
                    except socket.error as e:
                        self.log_message(f"Error accepting connection: {str(e)}")
                        continue

        except KeyboardInterrupt:
            self.log_message("Server shutdown by user")
        except Exception as e:
            self.log_message(f"Unexpected error: {str(e)}")
        finally:
            if server_socket:
                server_socket.close()

def main():
    # Create and start server
    server = NodeB(CONFIG['SERVER_IP'], CONFIG['SERVER_PORT'])
    server.start_server()

if __name__ == "__main__":
    main()
