from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

AES_IV_SIZE = 16

# Functions to perform AES256 encryption and decryption in GCM mode


# Perform encryption using AES256 in GCM Mode
def encrypt(message, key):
    iv = os.urandom(AES_IV_SIZE)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(message) + encryptor.finalize()
    return iv, cipher_text, encryptor.tag


# Perform decryption using AES256 in GCM Mode
def decrypt(cipher_message, key, iv, tag):
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(cipher_message) + decryptor.finalize()
