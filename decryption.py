from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import unpad
import base64

# Key derivation function
def derive_key(password: str, salt: bytes) -> bytes:
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    return key

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

# Main function to prompt for input and perform decryption
def main():
    print("Welcome to the decryption program.")
    encrypted_message = input("Enter the base64 encoded encrypted message: ")
    encryption_key = input("Enter the base64 encoded encryption key: ")

    try:
        decrypted_message = decrypt(encrypted_message, encryption_key)
        print(f"Decrypted message: {decrypted_message}")
    except Exception as e:
        print(f"Decryption failed: {e}")

if __name__ == "__main__":
    main()
