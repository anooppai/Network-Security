from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


# Functions to perform RSA encryption and decryption with 4096 key size.
# Input keys must be in .der format.


# Performs RSA encryption with specified key size
def rsa_encrypt(public_key_file, message):
    public_key = read_public_key(public_key_file)
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None)
    )


# Performs RSA decryption with specified key size
def rsa_decrypt(private_key_file, cipher_text):
    private_key = read_private_key(private_key_file)
    return private_key.decrypt(
        cipher_text,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None)
    )


# Function to read private key
def read_private_key(filename):
    if filename.endswith(".der"):
        try:
            with open(filename, "rb") as key_file:
                key = serialization.load_der_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend())
            return key
        except Exception, e:
            print 'Error reading private key: %s' % e
            exit()
    else:
        raise IOError('File format must be der.')


# Function to read public key
def read_public_key(filename):
    if filename.endswith(".der"):
        try:
            with open(filename, "rb") as key_file:
                key = serialization.load_der_public_key(
                    key_file.read(),
                    backend=default_backend())
                return key
        except Exception, e:
            print 'Error reading public key: %s' % e
            exit()
    else:
        raise IOError('File format must be der.')

