import socket
import os
import hashlib
import uuid
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from stegano import lsb
from PIL import Image
import base64
import secrets
from scapy.all import ARP, Ether, srp

def format_data(encrypted_key, encrypted_message, sha384_hash, sha512_hash, is_steganography):
    if is_steganography:
        return encrypted_key + b'::' + encrypted_message + b'::' + sha384_hash.encode() + b'::' + sha512_hash.encode()
    else:
        return encrypted_key + b'::' + encrypted_message + b'::' + sha384_hash.encode()

def check_root():
    return os.geteuid() == 0

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

CHUNK_SIZE = 4096

def get_mac_address():
    mac = hex(uuid.getnode()).replace('0x', '').upper()
    return ':'.join(mac[i:i+2] for i in range(0, 12, 2))

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

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

def load_rsa_key_pair(private_key_path, public_key_path):
    with open(private_key_path, "rb") as private_file:
        private_key = serialization.load_pem_private_key(
            private_file.read(),
            password=None,
            backend=default_backend()
        )

    with open(public_key_path, "rb") as public_file:
        public_key = serialization.load_pem_public_key(
            public_file.read(),
            backend=default_backend()
        )

    return private_key, public_key

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def encrypt_with_rsa(public_key, message):
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_with_rsa(private_key, encrypted_message):
    return private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def encrypt_with_aes(key, data):
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return iv + encryptor.update(data) + encryptor.finalize()

def decrypt_with_aes(key, data):
    iv = data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(data[16:]) + decryptor.finalize()

def hash_blake2(data):
    return hashlib.blake2b(data).hexdigest()

def embed_message_in_image(image_path, message):
    secret_image_path = "secret_image.png"
    secret_image = lsb.hide(image_path, message)
    secret_image.save(secret_image_path)
    return secret_image_path

def bytes_to_base64(bytes):
    return base64.b64encode(bytes)

def base64_to_bytes(base):
    return base64.b64decode(base)

def send_in_chunks(data, sock):
    bytes_sent = 0
    while bytes_sent < len(data):
        sent = sock.send(data[bytes_sent:])
        if sent == 0:
            raise RuntimeError("Socket connection broken")
        bytes_sent = sent + bytes_sent
        print(f"Data sent: {data[bytes_sent - sent:bytes_sent]}")  # print statement to check the data being sent

def receive_in_chunks(sock, length):
    chunks = []
    bytes_recd = 0
    while bytes_recd < length:
        chunk = sock.recv(min(length - bytes_recd, 2048))
        if chunk == b'':
            raise RuntimeError("Socket connection broken")
        chunks.append(chunk)
        bytes_recd = bytes_recd + len(chunk)
        print(f"Data received: {chunk}")  # print statement to check the data being received
    return b''.join(chunks)

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
                data_length = int.from_bytes(receive_in_chunks(conn, 4), 'big')
                data = receive_in_chunks(conn, data_length)
                if not data:
                    break

                print(f"Received data: {data}")

                received_data = data.split(b'::')
                print(f"Received encrypted_key: {received_data[0].hex()}")
                print(f"Received encrypted_message: {received_data[1]}")

                is_steganography = (len(received_data) == 5)

                encrypted_key, encrypted_message, sha384_hash, sha512_hash = received_data[:4]

                if is_steganography:
                    received_data = received_data[4:]
                    sha384_hash_steg = received_data[0]
                    decrypted_message, is_valid = verify_and_decrypt_steganography(encrypted_message, received_data[1:], sha384_hash, sha512_hash, sha384_hash_steg)
                    if not is_valid:
                        continue
                else:
                    decrypted_message = decrypt_with_aes(private_key, encrypted_message)

                calculated_sha512_hash = hashlib.sha512(decrypted_message).hexdigest()
                if calculated_sha512_hash.hex() != sha512_hash.decode():
                    print("Error: SHA-512 hash does not match.")
                    break
                print(f"SHA-512 Hash of the encrypted message: {calculated_sha512_hash.hex()}")

                calculated_sha384_hash = hashlib.sha384(decrypted_message).hexdigest()
                if calculated_sha384_hash.hex() != sha384_hash.decode():
                    print("Error: SHA-384 hash does not match.")
                    break
                print(f"SHA-384 Hash of the message: {calculated_sha384_hash.hex()}")

                conn.sendall(b"Hashes verified and message received successfully.")

                with open("received_message", 'wb') as file:
                    file.write(decrypted_message)

                conn.sendall(b"Message saved to file 'received_message'.")

def verify_and_decrypt_steganography(encrypted_message, received_data, sha384_hash, sha512_hash, sha384_hash_steg):
    is_valid = False
    decrypted_message = None

    if received_data:
        try:
            key = secrets.token_bytes(32)
            cipher = Cipher(algorithms.AES(key), modes.CFB(received_data[0]), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
            is_valid = True
        except hashlib.InvalidKey as e:
            print(f"Error: Invalid AES key. Reason: {e}")
            return None, False

        if decrypted_message:
            if hashlib.sha384(decrypted_message).hexdigest() == sha384_hash:
                is_valid = True
            else:
                print("Error: SHA-384 hash does not match.")
        else:
            print("Error: Failed to decrypt message.")
    else:
        print("Error: No data provided for steganography.")

    return decrypted_message, is_valid

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

def start_client(host, port):
    mac_address = get_mac_address()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, port))
        print(f"Connected to {host}:{port}")
        print(f"Client MAC Address: {mac_address}")
        if check_root():
            print(f"Server MAC Address: {get_ip_mac_address(host)}")
        else:
            print("Getting the MAC Address of another device requires administrator permissions")

        serialized_public_key = client_socket.recv(1024)
        public_key = serialization.load_pem_public_key(serialized_public_key, backend=default_backend())

        while True:
            input_type = input("Enter 'message' to send a message, 'file' to send the contents of a file (or 'exit' to quit): ").strip().lower()

            if input_type == 'exit':
                break
            elif input_type == 'message':
                user_input = input("Enter the message to send: ").encode('utf-8')
                message = user_input
                sha384_hash = hashlib.sha384(user_input).hexdigest()
                sha512_hash = hashlib.sha512(user_input).hexdigest()
                is_steganography = False
            elif input_type == 'file':
                file_path = input("Enter the path of the file: ").strip()
                if os.path.isfile(file_path):
                    with open(file_path, 'rb') as file:
                        message = file.read()
                    sha384_hash = hashlib.sha384(message).hexdigest()
                    sha512_hash = hashlib.sha512(message).hexdigest()
                    is_steganography = False
                else:
                    print("File not found. Please try again.")
                    continue

            use_steg = input("Use steganography techniques? An image will be requested (Y/N)").strip().lower()
            if use_steg == 'y':
                image_path = input("Enter the path of the image: ").strip()
                if os.path.isfile(image_path):
                    try:
                        secret_image_path = embed_message_in_image(image_path, message)
                        message = base64.b64encode(message)
                        encrypted_message = secret_image_path.encode()
                        is_steganography = True
                    except lsb.exceptions.ImageException as e:
                        print(f"Error: Failed to embed the message into the steganography image. Reason: {e}")
                        continue
                else:
                    print("Image not found. Please try again.")
                    continue

            aes_key = generate_aes_key()
            encrypted_message = encrypt_with_aes(aes_key, message)
            encrypted_key = encrypt_with_rsa(public_key, aes_key)
            encrypted_message_hash_sha512 = hashlib.sha512(encrypted_message).hexdigest()

            print(f"SHA-384 Hash of the message: {sha384_hash}")
            print(f"Encrypted message: {encrypted_message}")
            print(f"SHA-512 Hash of the encryption: {encrypted_message_hash_sha512}")

            data_to_send = format_data(encrypted_key, encrypted_message, sha384_hash, sha512_hash, is_steganography, encrypted_message_hash_sha512)

            client_socket.sendall(data_to_send)

            response = client_socket.recv(1024)
            print(f"Server response: {response.decode('utf-8')}")

def main():
    mode = input("Enter 'client' to start a connection or 'server' to wait for a connection: ").strip().lower()
    host = get_host_ip()
    port = 12345
    if mode == 'client':
        target_ip = input("Enter the destination IP: ").strip()
        start_client(target_ip, port)
    elif mode == 'server':
        start_server(host, port)
    else:
        print("Invalid mode. Use 'client' or 'server'.")

if __name__ == "__main__":
    main()