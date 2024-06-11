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
    # Convertir 'localhost' a '127.0.0.1'
    if ip_address == 'localhost':
        ip_address = '127.0.0.1'
    # Crear un paquete ARP para preguntar por la dirección MAC del IP objetivo
    arp_request = ARP(pdst=ip_address)
    # Crear una trama Ethernet para la solicitud ARP
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    # Combinar ambas para formar el paquete completo
    arp_request_broadcast = broadcast / arp_request
    # Enviar el paquete y recibir la respuesta
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # Si hay una respuesta, obtener la dirección MAC del campo hwsrc
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
        print(f"Esperando conexiones en {host}:{port}...")

        conn, addr = server_socket.accept()
        with conn:
            print(f"Conectado a {addr}")
            print(f"MAC Address del servidor: {mac_address}")
            if check_root():
                print(f"MAC Address del cliente: {get_ip_mac_address(addr[0])}")
            else:
                print("Obtener la Mac Address de otro equipo requiere de permisos de administrador")

            # Enviar la llave pública al cliente
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
                    print("Error: Formato de datos recibido incorrecto.")
                    break

                if is_steganography:
                    with open("received_image.png", "wb") as img_file:
                        img_file.write(base64_to_bytes(encrypted_message)) # no es realmente encriptado, es la imagen

                    calculated_blake2_hash = hash_blake2(base64_to_bytes(encrypted_message))
                    if calculated_blake2_hash != blake2_hash.decode():
                        print("Error: BLAKE2 hash no coincide.")
                        break
                    print(f"BLAKE2 Hash de la imagen: {calculated_blake2_hash}")
                    print(f"Tamaño de la imagen recibida: {os.path.getsize('received_image.png')} bytes")

                    revealed_message = lsb.reveal("received_image.png")
                    print(f"Mensaje desencriptado y revelado de la imagen: {revealed_message}")
                    encrypted_message = revealed_message.encode()

                # Verificar hash SHA-512 del mensaje encriptado
                calculated_sha512_hash = hashlib.sha512(encrypted_message).hexdigest()
                if calculated_sha512_hash != sha512_hash.decode():
                    print("Error: SHA-512 hash no coincide.")
                    break
                print(f"SHA-512 Hash del mensaje encriptado: {calculated_sha512_hash}")

                # Verificar hash SHA-384 del mensaje original
                decrypted_message = decrypt_with_rsa(private_key, base64_to_bytes(encrypted_message))

                calculated_sha384_hash = hashlib.sha384(decrypted_message).hexdigest()
                if calculated_sha384_hash != sha384_hash.decode():
                    print("Error: SHA-384 hash no coincide.")
                    break
                print(f"SHA-384 Hash del mensaje: {calculated_sha384_hash}")

                conn.sendall(b"Hashes verificados y mensaje recibido correctamente.")

                with open("received_message", 'wb') as file:  # Cambiado a 'wb'
                    file.write(decrypted_message)

                conn.sendall(b"Mensaje guardado en archivo 'received_message'.")

def start_client(host, port):
    mac_address = get_mac_address()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, port))
        print(f"Conectado a {host}:{port}")
        print(f"MAC Address del cliente: {mac_address}")
        if check_root():
            print(f"MAC Address del servidor: {get_ip_mac_address(host)}")
        else:
            print("Obtener la Mac Address de otro equipo requiere de permisos de administrador")

        # Recibir la llave pública del servidor
        serialized_public_key = client_socket.recv(1024)
        public_key = serialization.load_pem_public_key(serialized_public_key)

        while True:
            input_type = input("Ingrese 'mensaje' para enviar un mensaje, 'archivo' para enviar el contenido de un archivo (o 'salir' para terminar): ").strip().lower()

            if input_type == 'salir':
                break
            elif input_type == 'mensaje':
                message = input("Ingrese el mensaje a enviar: ").encode('utf-8')
            elif input_type == 'archivo':
                file_path = input("Ingrese la ruta del archivo: ").strip()
                if os.path.isfile(file_path):
                    with open(file_path, 'rb') as file:
                        message = file.read()
                else:
                    print("Archivo no encontrado. Intente de nuevo.")
                    continue

            use_steg = input("Usar técnicas de esteganografía? Se pedirá una imagen (S/N)").strip().lower()
            # Calcular el hash SHA-384 del mensaje
            message_hash_sha384 = hashlib.sha384(message).hexdigest

()
            # Encriptar el mensaje con la llave pública RSA
            encrypted_message = bytes_to_base64(encrypt_with_rsa(public_key, message))
            # Calcular el hash SHA-512 de la encripción
            encrypted_message_hash_sha512 = hashlib.sha512(encrypted_message).hexdigest()

            if use_steg == 'S':
                image_path = input("Ingrese la ruta de la imagen: ").strip()
                if os.path.isfile(image_path):
                    secret_image_path = embed_message_in_image(image_path, encrypted_message.decode())
                    with open(secret_image_path, 'rb') as img_file:
                        encrypted_message = bytes_to_base64(img_file.read())
                else:
                    print("Imagen no encontrada. Intente de nuevo.")
                    continue

            print(f"SHA-384 Hash del mensaje: {message_hash_sha384}")
            print(f"Mensaje encriptado: {encrypted_message}")
            print(f"SHA-512 Hash de la encripción: {encrypted_message_hash_sha512}")

            # Calcular el hash BLAKE2 de la imagen con esteganografía (si aplica)
            if input_type == 'imagen':
                image_hash_blake2 = hash_blake2(base64_to_bytes(encrypted_message))
                print(f"BLAKE2 Hash de la imagen con esteganografía: {image_hash_blake2}")
                print(f"Tamaño del archivo de la imagen: {os.path.getsize(secret_image_path)} bytes")
                data_to_send = encrypted_message + b'::' + message_hash_sha384.encode() + b'::' + encrypted_message_hash_sha512.encode() + b'::' + image_hash_blake2.encode()
            else:
                data_to_send = encrypted_message + b'::' + message_hash_sha384.encode() + b'::' + encrypted_message_hash_sha512.encode()

            send_in_chunks(client_socket, data_to_send)
            response = client_socket.recv(1024)
            print(f"Respuesta del servidor: {response.decode('utf-8')}")

def main():
    mode = input("Ingrese 'cliente' para iniciar una conexión o 'servidor' para esperar una conexión: ").strip().lower()
    host = 'localhost'
    port = 12345

    if mode == 'cliente':
        target_ip = input("Ingrese la IP de destino: ").strip()
        start_client(target_ip, port)
    elif mode == 'servidor':
        start_server(host, port)
    else:
        print("Modo no válido. Use 'cliente' o 'servidor'.")

if __name__ == "__main__":
    main()
