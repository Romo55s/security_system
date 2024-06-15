import socket
import os
import hashlib
import uuid
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from stegano import lsb
from PIL import Image
import base64
from scapy.all import ARP, Ether, srp


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
        key_size=2048
    )
    public_key = private_key.public_key()
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


def send_in_chunks(socket, data):
    total_size = len(data)
    socket.sendall(total_size.to_bytes(8, byteorder='big'))
    for i in range(0, total_size, CHUNK_SIZE):
        chunk = data[i:i+CHUNK_SIZE]
        socket.sendall(chunk)


def receive_in_chunks(socket):
    total_size = int.from_bytes(socket.recv(8), byteorder='big')
    data = bytearray()
    while len(data) < total_size:
        chunk = socket.recv(CHUNK_SIZE)
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def start_server(host, port):
    private_key, public_key = generate_rsa_key_pair()
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
                data = receive_in_chunks(conn)
                if not data:
                    break

                received_data = data.split(b'::')
                if len(received_data) == 4:
                    encrypted_message, sha384_hash, sha512_hash, blake2_hash = received_data
                    is_steganography = True
                elif len(received_data) == 3:
                    encrypted_message, sha384_hash, sha512_hash = received_data
                    blake2_hash = None
                    is_steganography = False
                else:
                    print("Error: Incorrect data format received.")
                    break

                if is_steganography:
                    with open("received_image.png", "wb") as img_file:
                        img_file.write(base64_to_bytes(encrypted_message))

                    calculated_blake2_hash = hash_blake2(base64_to_bytes(encrypted_message))
                    if calculated_blake2_hash != blake2_hash.decode():
                        print("Error: BLAKE2 hash does not match.")
                        break
                    print(f"BLAKE2 Hash of the image: {calculated_blake2_hash}")
                    print(f"Received image size: {os.path.getsize('received_image.png')} bytes")

                    revealed_message = lsb.reveal("received_image.png")
                    print(f"Decrypted and revealed message from the image: {revealed_message}")
                    encrypted_message = revealed_message.encode()

                calculated_sha512_hash = hashlib.sha512(encrypted_message).hexdigest()
                if calculated_sha512_hash != sha512_hash.decode():
                    print("Error: 512 hash does not match.")
                    break
                print(f"SHA-512 Hash of the encrypted message: {calculated_sha512_hash}")

                decrypted_message = decrypt_with_rsa(private_key, base64_to_bytes(encrypted_message))

                calculated_sha384_hash = hashlib.sha384(decrypted_message).hexdigest()
                if calculated_sha384_hash != sha384_hash.decode():
                    print("Error: SHA-384 hash does not match.")
                    break
                print(f"SHA-384 Hash of the message: {calculated_sha384_hash}")

                conn.sendall(b"Hashes verified and message received successfully.")

                with open("received_message", 'wb') as file:
                    file.write(decrypted_message)

                conn.sendall(b"Message saved to file 'received_message'.")

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
        public_key = serialization.load_pem_public_key(serialized_public_key)

        while True:
            input_type = input("Enter 'message' to send a message, 'file' to send the contents of a file (or 'exit' to quit): ").strip().lower()

            if input_type == 'exit':
                break
            elif input_type == 'message':
                message = input("Enter the message to send: ").encode('utf-8')
            elif input_type == 'file':
                file_path = input("Enter the path of the file: ").strip()
                if os.path.isfile(file_path):
                    with open(file_path, 'rb') as file:
                        message = file.read()
                else:
                    print("File not found. Please try again.")
                    continue

            use_steg = input("Use steganography techniques? An image will be requested (Y/N)").strip().lower()
            message_hash_sha384 = hashlib.sha384(message).hexdigest()
            encrypted_message = bytes_to_base64(encrypt_with_rsa(public_key, message))
            encrypted_message_hash_sha512 = hashlib.sha512(encrypted_message).hexdigest()

            if use_steg == 'y':
                image_path = input("Enter the path of the image: ").strip()
                if os.path.isfile(image_path):
                    secret_image_path = embed_message_in_image(image_path, encrypted_message.decode())
                    with open(secret_image_path, 'rb') as img_file:
                        encrypted_message = bytes_to_base64(img_file.read())
                else:
                    print("Image not found. Please try again.")
                    continue

            print(f"SHA-384 Hash of the message: {message_hash_sha384}")
            print(f"Encrypted message: {encrypted_message}")
            print(f"SHA-512 Hash of the encryption: {encrypted_message_hash_sha512}")

            if input_type == 'image':
                image_hash_blake2 = hash_blake2(base64_to_bytes(encrypted_message))
                print(f"BLAKE2 Hash of the image with steganography: {image_hash_blake2}")
                print(f"File size of the image: {os.path.getsize(secret_image_path)} bytes")
                data_to_send = encrypted_message + b'::' + message_hash_sha384.encode() + b'::' + encrypted_message_hash_sha512.encode() + b'::' + image_hash_blake2.encode()
            else:
                data_to_send = encrypted_message + b'::' + message_hash_sha384.encode() + b'::' + encrypted_message_hash_sha512.encode()

            send_in_chunks(client_socket, data_to_send)
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
