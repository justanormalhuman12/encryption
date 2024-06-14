from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64

# Key derivation function
def derive_key(password: str, salt: bytes) -> bytes:
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    return key

# Encryption function that returns the encryption key
def encrypt(plain_text: str, password: str) -> (str, str):
    salt = get_random_bytes(16)  # Generate a random salt
    key = derive_key(password, salt)  # Derive the key using the password and salt
    iv = get_random_bytes(16)  # Generate a random IV

    # Initialize the cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Pad the plain text to be a multiple of block size
    pad_len = AES.block_size - len(plain_text) % AES.block_size
    padded_data = plain_text + (chr(pad_len) * pad_len)

    # Encrypt the padded data
    cipher_text = cipher.encrypt(padded_data.encode())

    # Combine salt, iv, and cipher_text for storage/transfer
    encrypted_data = base64.b64encode(salt + iv + cipher_text).decode('utf-8')
    
    # Return both the encrypted message and the key (encoded for safe transfer/storage)
    return encrypted_data, base64.b64encode(key).decode('utf-8')

# Decryption function
def decrypt(encrypted_data: str, encoded_key: str) -> str:
    encrypted_data = base64.b64decode(encrypted_data.encode('utf-8'))
    key = base64.b64decode(encoded_key.encode('utf-8'))

    # Extract the salt, iv, and cipher_text from the encrypted data
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    cipher_text = encrypted_data[32:]

    # Initialize the cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt the cipher text
    padded_data = cipher.decrypt(cipher_text)

    # Unpad the decrypted data
    pad_len = padded_data[-1]
    plain_text = padded_data[:-pad_len]

    return plain_text.decode('utf-8')

# Main loop to allow input and encryption
def main():
    password = "strongpassword123"

    while True:
        message = input("Enter your message (or type 'exit' to quit): ")
        if message.lower() == 'exit':
            break

        encrypted_message, encryption_key = encrypt(message, password)
        print(f"Message: {message}")
        print(f"Encrypted: {encrypted_message}")
        print(f"Encryption Key: {encryption_key}")
        print("\n")

if __name__ == "__main__":
    main()
