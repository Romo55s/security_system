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

def generate_aes_key():
    return secrets.token_bytes(32)

def format_data(encrypted_key, encrypted_message, sha384_hash, sha512_hash, is_steganography):
    steg_flag = b'1' if is_steganography else b'0'
    return encrypted_key + b'::' + encrypted_message + b'::' + sha384_hash.encode() + b'::' + sha512_hash.encode() + b'::' + steg_flag

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

def encrypt_with_rsa_inverted(public_key, message):
    chunk_size = public_key.key_size // 8 - 42
    encrypted_chunks = []
    for i in range(0, len(message), chunk_size):
        chunk = message[i:i + chunk_size]
        encrypted_chunk = public_key.encrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_chunks.append(encrypted_chunk)
    return b''.join(encrypted_chunks)

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

def validate_blake2_hash(received_hash, data):
    calculated_hash = hash_blake2(data)
    return received_hash == calculated_hash

def start_server(host, port):
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

            while True:
                public_key = conn.recv(1024)
                serialized_public_key = public_key.decode()

                try:
                    public_key = serialization.load_pem_public_key(
                        serialized_public_key.encode(),
                        backend=default_backend()
                    )
                except serialization.InvalidKey as e:
                    print(f"Error: Failed to load public key. Reason: {e}")
                    continue

                # Enviar la llave pública al cliente
                conn.sendall(serialized_public_key.encode())

                data = receive_in_chunks(conn, 1024)
                Blake2_hash, encrypted_key, encrypted_message, sha512_hash, is_steganography = data.decode().split('::')

                Blake2_hash_server = hashlib.blake2b(encrypted_key + encrypted_message).hexdigest()

                if Blake2_hash_server != Blake2_hash:
                    print("Blake2 hash is not correct. Communication may have been altered.")
                else:
                    print("Blake2 hash is correct.")
                    if not is_steganography:
                        print("Extracting message...")
                        with open("secret_image.png", "rb") as img_file:
                            message = img_file.read()
                        os.remove("secret_image.png")
                    else:
                        message = base64.b64decode(encrypted_message)

                    aes_key = decrypt_with_rsa(generate_private_rsa_key(), base64.b64decode(encrypted_key))
                    decrypted_message = decrypt_with_aes(aes_key, message)

                    print("Validating sha512 hash...")
                    if sha512_hash == hashlib.sha512(decrypted_message).hexdigest():
                        print("sha512 hash is correct.")
                        print("Validating sha384 hash...")
                        sha384_hash_server = hashlib.sha384(decrypted_message).hexdigest()
                        if sha384_hash_server == sha384_hash:
                            print("sha384 hash is correct.")
                            print("The message is ready.")
                            conn.sendall(b"READY")
                        else:
                            print("sha384 hash is not correct. Eliminating the message.")
                            conn.sendall(b"HASH_ERROR")
                    else:
                        print("sha512 hash is not correct. Eliminating the message.")
                        conn.sendall(b"HASH_ERROR")

                conn.sendall(b"OK")

                break

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

        # Solicitar llave pública al servidor y mostrar y capturar la MAC address del otro equipo
        public_key_request = b"REQUEST_PUBLIC_KEY"
        client_socket.sendall(public_key_request)
        server_mac = receive_in_chunks(client_socket, 18).decode()
        print(f"Server MAC Address: {server_mac}")

        # Enviar la llave pública
        private_key, public_key = generate_rsa_key_pair()
        serialized_public_key = serialize_public_key(public_key)
        client_socket.sendall(serialized_public_key)

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
            encrypted_key = encrypt_with_rsa_inverted(public_key, aes_key)

            Blake2_hash = hashlib.blake2b(encrypted_key + encrypted_message).hexdigest()

            data_to_send = format_data(Blake2_hash, encrypted_key, encrypted_message, sha512_hash, is_steganography)
            client_socket.sendall(data_to_send)

            response = client_socket.recv(1024)
            print(f"Server response: {response.decode('utf-8')}")

            if not is_steganography:
                print("Extracting message...")
                with open("secret_image.png", "rb") as img_file:
                    message = img_file.read()
                os.remove("secret_image.png")

            print("Validating Blake2 hash...")
            if Blake2_hash == response.decode():
                print("Blake2 hash is correct.")
                if not is_steganography:
                    print("Decrypting the message...")
                    decrypted_message = decrypt_with_aes(aes_key, base64.b64decode(encrypted_message))
                    print("Validating sha512 hash...")
                    if sha512_hash == hashlib.sha512(decrypted_message).hexdigest():
                        print("sha512 hash is correct.")
                        print("Validating sha384 hash...")
                        if sha384_hash == hashlib.sha384(decrypted_message).hexdigest():
                            print("sha384 hash is correct.")
                            print("The message is ready.")
                        else:
                            print("sha384 hash is not correct. Eliminating the message.")
                    else:
                        print("sha512 hash is not correct. Eliminating the message.")
                else:
                    print("The message is ready.")
            else:
                print("Blake2 hash is not correct. Communication may have been altered. Eliminating the message.")

        print("Connection closed.")

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
