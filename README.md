# Secure Message Transfer System

This system facilitates secure message transfer using reverse RSA encryption, SHA and BLAKE2 hashing, and optional steganography. It supports sending messages or files, ensuring data integrity and confidentiality.

## Requirements Addressed

1. **Public Key Exchange and MAC Address Capture**: 
    - The system requests the public key from the counterpart and captures the MAC address.
2. **Message or File Transfer**: 
    - The user can input a message or select a file to send.
3. **SHA-384 Hash Generation**: 
    - Generates an SHA-384 hash of the message.
4. **Reverse RSA Encryption**: 
    - Encrypts the message using the received public key.
5. **SHA-512 Hash Generation**: 
    - Generates an SHA-512 hash of the encrypted message.
6. **Optional Steganography**: 
    - Allows the user to choose an object (image) to hide the encrypted message.
7. **BLAKE2 Hash Generation**: 
    - Generates a BLAKE2 hash of the hidden message.
8. **Message Transmission and Validation**: 
    - The message is sent to another device where the system performs the reverse operations and validation.

## Usage

### Prerequisites

- Python 3.x
- Required Python packages: `cryptography`, `stegano`, `Pillow`, `scapy`

### Installation

1. Install the required packages:
    ```sh
    pip install cryptography stegano Pillow scapy
    ```

2. Ensure the script has execution permissions:
    ```sh
    chmod +x secure_message_transfer.py
    ```

### Running the Script

1. Start the server on the receiving machine:
    ```sh
    python secure_message_transfer.py
    ```

2. Start the client on the sending machine:
    ```sh
    python secure_message_transfer.py
    ```

### Script Workflow

#### Server

1. Generates RSA key pair (public and private keys).
2. Listens for incoming connections.
3. Sends the public key to the client.
4. Receives encrypted message, hashes, and optional steganographic data.
5. Validates BLAKE2 hash (if steganography used).
6. Extracts the message from the image (if steganography used).
7. Validates SHA-512 hash of the encrypted message.
8. Decrypts the message using the private key.
9. Validates SHA-384 hash of the original message.
10. Sends confirmation to the client.

#### Client

1. Connects to the server.
2. Receives the public key from the server.
3. Captures or selects the message/file to send.
4. Generates SHA-384 hash of the message.
5. Encrypts the message using the server's public key.
6. Generates SHA-512 hash of the encrypted message.
7. Optionally hides the encrypted message in an image.
8. Generates BLAKE2 hash of the steganographic image (if used).
9. Sends the encrypted message, hashes, and optional steganographic data to the server.
10. Receives confirmation from the server.

## Example Usage

### Starting the Server

```sh
python secure_message_transfer.py
```

### Starting the Client
```sh
python secure_message_transfer.py
```

### Commands within the Client
```plaintext
Enter 'message' to send a message, 'file' to send a file (or 'exit' to terminate):file
Enter the file path: /path/to/file.txt 
Use steganography techniques? (Y/N): Y 
Enter the image path: /path/to/image.png
```

### Send a file
```plaintext
Enter 'message' to send a message, 'file' to send a file (or 'exit' to terminate): file 
Enter the file path: /path/to/file.txt 
Use steganography techniques? (Y/N): Y 
Enter the image path: /path/to/image.png
```

### Security Considerations
-   Ensure the script is run with appropriate permissions to access network interfaces and files.
-   Keep the private key secure and do not share it.
-   Use strong passphrases for key protection.
