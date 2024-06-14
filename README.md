# AES Encryption and Decryption Program

This Python program demonstrates AES encryption and decryption using a password-based key derivation (PBKDF2) and AES in CBC mode.

## Features

- **Encryption**: Encrypts a plaintext message using AES with a randomly generated salt and IV.
- **Decryption**: Decrypts an encrypted message using the provided encryption key derived from a password.

## Requirements

- Python 3.x
- pycryptodome library (`pip install pycryptodome`)

## Usage

1. **Encryption:**
   - Run the program and enter a plaintext message.
   - Enter a password to derive the encryption key.
   - The program will display the encrypted message and the base64 encoded encryption key.

2. **Decryption:**
   - Copy the base64 encoded encrypted message and the encryption key from the encryption step.
   - Run the program again and enter the encrypted message and encryption key when prompted.
   - The program will decrypt the message and display the original plaintext.

## Example

Here's an example of how to use the program:

1. Encrypting a message:
