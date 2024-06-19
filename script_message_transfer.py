#1
import socket
import os
import hashlib
import uuid
import base64
import secrets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from stegano import lsb
from PIL import Image
from scapy.all import ARP, Ether, srp

#2
def format_data(encrypted_message, sha384_hash, sha512_hash, blake2_hash, is_steganography):
    print("is_steganography function", is_steganography)
    if is_steganography:
        print("format data function sha384_hash", sha384_hash)
        print("format data function sha512_hash", sha512_hash)
        return encrypted_message + b'::' + sha384_hash + b'::' + sha512_hash + b'::' + blake2_hash
    else:
        print("format data function sha384_hash", sha384_hash)
        print("format data function sha512_hash", sha512_hash)
        return encrypted_message + b'::' + sha384_hash + b'::' + sha512_hash

#3
def check_root():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False
#4
def get_ip_mac_address(ip_address):
    if ip_address == 'localhost':
        ip_address = '127.0.0.1'
    arp_request = ARP(pdst=ip_address)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        return None
#5
CHUNK_SIZE = 4096
#6
def get_mac_address():
    mac = hex(uuid.getnode()).replace('0x', '').upper()
    return ':'.join(mac[i:i+2] for i in range(0, 12, 2))
#7
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=16384,
    )
    public_key = private_key.public_key()
    return private_key, public_key
#8
def save_rsa_key_pair(private_key, public_key, private_key_path, public_key_path):
    with open(private_key_path, "wb") as private_file:
        private_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(public_key_path, "wb") as public_file:
        public_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
#9
def load_rsa_key_pair(private_key_path, public_key_path):
    with open(private_key_path, "rb") as private_file:
        private_key = serialization.load_pem_private_key(
            private_file.read(),
            password=None,
        )

    with open(public_key_path, "rb") as public_file:
        public_key = serialization.load_pem_public_key(
            public_file.read(),
        )

    return private_key, public_key
#10
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
#11
def encrypt_with_rsa(public_key, message):
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
#12
def decrypt_with_rsa(private_key, encrypted_message):
    return private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
#13
def hash_blake2(data):
    return hashlib.blake2b(data).hexdigest()
#14
def embed_message_in_image(image_path, message):
    secret_image_path = "secret_image.png"
    try:
        secret_image = lsb.hide(image_path, message)
        secret_image.save(secret_image_path)
        return secret_image_path
    except lsb.exceptions.ImageException as e:
        print(f"Error: Failed to embed the message into the steganography image. Reason: {e}")
        return None
#15
def bytes_to_base64(bytes):
    return base64.b64encode(bytes)
#16
def base64_to_bytes(base):
    return base64.b64decode(base)
#17
def send_in_chunks(socket, data):
    total_size = len(data)
    socket.sendall(total_size.to_bytes(8, byteorder='big'))
    for i in range(0, total_size, CHUNK_SIZE):
        chunk = data[i:i+CHUNK_SIZE]
        socket.sendall(chunk)
#18
def receive_in_chunks(socket):
    total_size = int.from_bytes(socket.recv(8), byteorder='big')
    data = bytearray()
    while len(data) < total_size:
        chunk = socket.recv(CHUNK_SIZE)
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)
#19
def validate_blake2_hash(received_hash, data):
    calculated_hash = hash_blake2(data)
    return received_hash == calculated_hash
#20
def start_server(host, port):
    private_key_path = "private_key.pem"
    public_key_path = "public_key.pem"
    if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
        private_key, public_key = generate_rsa_key_pair()
        save_rsa_key_pair(private_key, public_key, private_key_path, public_key_path)
    else:
        private_key, public_key = load_rsa_key_pair(private_key_path, public_key_path)
    serialized_public_key = serialize_public_key(public_key)
    mac_address = get_mac_address()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen()
        print(f"Waiting for connections on {host}:{port}...")
        while True:
            conn, addr = server_socket.accept()
            with conn:
                print(f"Connected to {addr}")
                print(f"Server MAC Address: {mac_address}")
                if check_root():
                    print(f"Client MAC Address: {get_ip_mac_address(addr[0])}")
                else:
                    print("Getting the MAC Address of another device requires administrator permissions")
                conn.sendall(serialized_public_key)
                while True:
                    try:
                        flag = False
                        data = receive_in_chunks(conn)
                        if not data:
                            break
                        received_data = data.split(b'::')
                        print("received_data", received_data)
                        print("len recived data", len(received_data))
                        if len(received_data) == 4:
                            encrypted_message, received_sha384_hash, received_sha512_hash, blake2_hash = received_data
                            flag = True
                            print("Steganography", flag)
                        elif len(received_data) == 3:
                            encrypted_message, received_sha384_hash, received_sha512_hash = received_data
                            blake2_hash = None
                            flag = False
                            print("Steganography", flag)
                        else:
                            print("Error: Invalid data received.")
                            break
                        print(f"Received data: {received_data}")
                        if flag:
                            img_path = "received_image.png"
                            with open(img_path, "wb") as img_file:
                                img_file.write(base64_to_bytes(encrypted_message))
                            
                            calculated_blake2_hash = hash_blake2(base64_to_bytes(encrypted_message))
                            if calculated_blake2_hash != blake2_hash.decode():
                                print("Error: The received data was modified, blake2 hash dont match")
                                try:
                                    if os.path.exists(img_path):
                                        os.remove(img_path)
                                        print(f"Deleted {img_path} the received image.")
                                except Exception as e:
                                    print(f"An error occurred while deleting the received image: {e}")
                                break
                            print(f"BLAKE2 hash of the image: {calculated_blake2_hash}")
                            print(f"Size of the image received: {os.path.getsize(img_path)} bytes")
                            
                            revealed_message = lsb.reveal(img_path)
                            print(f"Message decrypted and image reveal: {revealed_message}")
                            encrypted_message = revealed_message.encode()
                            
                        calculated_sha512_hash = hashlib.sha512(encrypted_message).hexdigest()
                        
                        print(f"SHA512 hash of the calculated message: {calculated_sha512_hash}")
                        print(f"SHA512 hash of the received message: {received_sha512_hash.decode()}")
                        if calculated_sha512_hash != received_sha512_hash.decode():
                            print("Error: The received data was modified sha512 hash.")
                            break
                        print(f"SHA512 hash of the received message: {calculated_sha512_hash}")
                        
                        decrypted_message = decrypt_with_rsa(private_key, base64_to_bytes(encrypted_message))
                        
                        calculated_sha384_hash = hashlib.sha384(encrypted_message).hexdigest()
                        print(f"SHA384 hash of the calculated message: {calculated_sha384_hash}")
                        print(f"SHA384 hash of the received message: {received_sha384_hash.decode()}")
                        if calculated_sha384_hash != received_sha384_hash.decode():
                            print("Error: The received data was modified sha384 hash.")
                            break
                        print(f"SHA384 hash of the received message: {calculated_sha384_hash}")
                        
                        conn.sendall(b"Message received successfully.")
                        
                        with open("received_message.txt", "wb") as file:
                            file.write(decrypted_message)
                        print("Message saved to received_message file.")
                    except socket.error as e:
                        print(f"An error occurred: {e}")

#21                        break
def get_host_ip():
    try:
        s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        print("Unable to get Host Ip")
        return None

#22
def start_client(host, port):
    mac_address = get_mac_address()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, port))
        print(f"Connected to {host}:{port}")
        print(f"Client MAC Address: {mac_address}")

        serialized_public_key = client_socket.recv(4096)
        try:
            public_key = serialization.load_pem_public_key(serialized_public_key)
        except Exception as e:
            print(f"An error occurred while loading the public key: {e}")
            return

        while True:
            input_type = input("Enter 'm' to send a message, 'f' to send the contents of a file (or 'e' to quit): ").strip().lower()
            if input_type == "e":
                break
            elif input_type == "m":
                user_input = input("Enter the message or file contents to send: ")
                message = user_input.encode()
            elif input_type == "f":
                file_path = input("Enter the path of the file: ").strip()
                if os.path.isfile(file_path):
                    message = open(file_path, "rb").read()
                else:
                    print("File not found. Please enter a valid path.")
                    continue
            else:
                print("Invalid input. Please enter 'm', 'f' or 'e'.")
                continue

            is_steganography = input("Use steganography techniques? An image will be requested (Y/N): ").strip().lower()
            encrypted_message = bytes_to_base64(encrypt_with_rsa(public_key, message))
            sha384_hash = hashlib.sha384(encrypted_message).hexdigest()
            sha512_hash = hashlib.sha512(encrypted_message).hexdigest()

            if is_steganography.lower() == "y":
                image_path = input("Enter the path of the image: ").strip()
                if os.path.isfile(image_path):
                    secret_image_path = embed_message_in_image(image_path, encrypted_message.decode())

                    with open(secret_image_path, 'rb') as img_file:
                        encrypted_message = bytes_to_base64(img_file.read())
                    
                    blake2_hash = hashlib.blake2b(base64_to_bytes(encrypted_message)).hexdigest()
                    
                    data_to_send = format_data(encrypted_message, sha384_hash.encode(), sha512_hash.encode(), blake2_hash.encode(), is_steganography)
                    
                else:
                    print("Image not found.")
                    break
            else:
                print("Cooked sha384_hash", sha384_hash)
                print("Cooked sha512_hash", sha512_hash)

                data_to_send = format_data(encrypted_message, sha384_hash.encode(), sha512_hash.encode(), blake2_hash.encode(), is_steganography)

            try:
                send_in_chunks(client_socket, data_to_send)
                print("data_to_send", len(data_to_send))                
                response = client_socket.recv(1024)
                print(f"Server response: {response.decode('utf-8')}")
            except Exception as e:
                print(f"An error occurred while sending data or receiving response: {e}")
#23
def main():
    mode = input("Enter 'c' to start a connection or 's' to wait for a connection: ").strip().lower()
    host = "localhost"
    port = 12345
    if mode == 'c':
        target_ip = input("Enter the destination IP: ").strip()
        start_client(target_ip, port)
    elif mode == 's':
        start_server(host, port)
    else:
        print("Invalid mode. Use 'client' or 'server'.")

if __name__ == "__main__":
    main()
