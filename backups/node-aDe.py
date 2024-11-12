import socket
import sys
from typing import Tuple

# Configuration constants
CONFIG = {
    'SERVER_IP': '192.168.1.107',
    'SERVER_PORT': 12345,
    'BUFFER_SIZE': 1024,
    'ENCODING': 'utf-8'
}

class NodeA:
    def __init__(self, server_ip: str, server_port: int):
        self.server_ip = server_ip
        self.server_port = server_port
        
    def connect_to_server(self) -> Tuple[socket.socket, bool]:
        """Establish connection to the server"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.server_ip, self.server_port))
            return s, True
        except ConnectionRefusedError:
            print("Error: Connection refused. Please check if server is running.")
            return None, False
        except socket.gaierror:
            print("Error: Invalid IP address or hostname.")
            return None, False
        except Exception as e:
            print(f"Error connecting to server: {str(e)}")
            return None, False

    def send_data(self, data: str) -> bool:
        """Send data to server and receive response"""
        sock, connected = self.connect_to_server()
        if not connected:
            return False

        try:
            with sock:
                # Add modification to data
                modified_data = f"{data} I edit"
                
                # Send data
                sock.sendall(modified_data.encode(CONFIG['ENCODING']))
                print(f"Sent data: {modified_data}")

                # Receive response
                response = sock.recv(CONFIG['BUFFER_SIZE']).decode(CONFIG['ENCODING'])
                print(f"Received from Node B: {response}")
                return True

        except socket.timeout:
            print("Error: Connection timed out while sending/receiving data.")
        except Exception as e:
            print(f"Error during data transfer: {str(e)}")
        return False

def main():
    # Create NodeA instance
    node = NodeA(CONFIG['SERVER_IP'], CONFIG['SERVER_PORT'])
    
    try:
        while True:
            # Get input from user
            data = input("Enter the data to send (or 'quit' to exit): ")
            
            if data.lower() == 'quit':
                print("Exiting program...")
                break
                
            if not data.strip():
                print("Error: Please enter non-empty data.")
                continue
                
            # Send data
            node.send_data(data)
            
    except KeyboardInterrupt:
        print("\nProgram terminated by user.")
    except Exception as e:
        print(f"Unexpected error occurred: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
