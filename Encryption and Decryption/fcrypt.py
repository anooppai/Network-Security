import argparse
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature
import base64
import binascii
import struct
import os

# AES block size is 16 bytes
AES_BLOCK_SIZE = 16
# Use AES-256 encryption
AES_KEY_SIZE = 32
# Size of initialization vector is 16 bytes
AES_IV_SIZE = 16

#Function to sign the key
def make_signature(private_key, digest):
    signer =  private_key.signer(
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    signer.update(digest)
    signature = signer.finalize()
    return signature

#Function to verify the signature during decryption
def verify_sig(public_key, sign, message):
    verified = public_key.verifier(
        sign,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
            ),
        hashes.SHA256()
        )
    verified.update(message)
    verified.verify()

#Function to get the HMAC Digest
def get_hmac(key, message):
    hmac_value = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    hmac_value.update(message)
    return hmac_value.finalize()

#Function to perform RSA encryption
def rsa_encrypt(public_key, aes_key):
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))
    return encrypted_key

#Function to perform RSA Decryption
def rsa_decrypt(private_key, encrypted_key):
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))
    return aes_key

#Function to read the contents of a file
def get_file_contents(file):
    try:
        with open(file, 'rb') as filename:
            return filename.read()
    except Exception, e:
        print "Error in reading contents of file %s " % e
        exit()

#Function to return the public key from the given .der file
def get_public_key(file):
    if file.endswith(".der"):
        try:
            with open(file, "rb") as key_file:
                key = serialization.load_der_public_key(key_file.read(),
                       backend = default_backend())
                return key
        except Exception, e:
            print "Error retrieving public key : %s " % e
            exit()
    else:
        print "Improper file format. Must end with .der"
        exit()

#Function to return the private key from the given .der file
def get_private_key(file):
    if file.endswith(".der"):
        try:
            with open(file, "rb") as key_file:
                key = serialization.load_der_private_key(key_file.read(), password = None,
                      backend = default_backend())
                return key
        except Exception, e:
            print "Error retrieving private key : %s " % e
            exit()
    else:
        print "Improper file format. Must end with .der"
        exit()

#Function responsible for performing encryption
def perform_encryption(destination_public_key, sender_private_key, input_plaintext, cipher_text):
    print "Encryption process started"
    fd = open(cipher_text, 'wb')
    try:
        #Generate random key and IV for each run
        public_key = os.urandom(AES_KEY_SIZE)
        iv = os.urandom(AES_IV_SIZE)

        #Obtain HMAC and sign it by making use of the private key provided
        hmac_digest = get_hmac(public_key, input_plaintext)
        verified_digest = make_signature(sender_private_key, hmac_digest)

        print "Encrypting..."
        #Make use of AES-CTR mode to encrypt signed digest and plain text file
        cipher_text = Cipher(algorithms.AES(public_key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher_text.encryptor()
        cipher_text = encryptor.update(verified_digest) + encryptor.update(input_plaintext) + encryptor.finalize()

        #Use RSA to generate the final AES key
        final_key = rsa_encrypt(destination_public_key, public_key)

        #Write the cipher text to the output file
        print "writing encrypted text to file..."
        cipher_output = final_key + iv + cipher_text
        fd.write(cipher_output)
        fd.close()

    except Exception, ex:
        print "Error occurred during encryption %s " % ex
        fd.close()

#Function responsible for performing decryption
def perform_decryption(destination_private_key, sender_public_key, cipher_text, output_file):
    print "Starting decryption"
    fd = open(output_file, 'wb')

    try:
        key_size = (destination_private_key.key_size)/8

        #Extract key, IV and cipher text from the encrypted file
        final_key = cipher_text[:key_size]
        iv = cipher_text[key_size:key_size+AES_IV_SIZE]
        cipher_text = cipher_text[key_size+AES_IV_SIZE:]

        #Obtain AES key by using RSA decrpytion
        public_key = rsa_decrypt(destination_private_key, final_key)

        print "decrypting.."
        #Perform decryption by making use of AES-CTR
        cipher = Cipher(algorithms.AES(public_key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_text = decryptor.update(cipher_text) + decryptor.finalize()

        sender_public_key_size = (sender_public_key.key_size)/8
        verified_hmac = decrypted_text[:sender_public_key_size]
        decrypted_text = decrypted_text[sender_public_key_size:]

        #Obtain the HMAC digest and verify it's signature using public key provided
        hmac_digest = get_hmac(public_key, decrypted_text)
        verify_sig(sender_public_key, verified_hmac, hmac_digest)

        print "Writing decrypted file "
        fd.write(decrypted_text)
        print "Please find your decrypted file here : ", output_file
        fd.close()
    except InvalidSignature, ex:
        print "Invalid Signature %s " %ex
        fd.close()
    except Exception, e:
        print "Error while decrypting messsage %s " %e
        fd.close()

def main():
    try:
        #Wrong usage if the length of args is not as mentioned in the problem set
        if len(sys.argv) != 6:
            print "Incorrect input!"
            print "Usage : usage: fcrypt.py -e destination_public_key_filename sender_private_key_filename input_plaintext_file ciphertext_file"
            print "or"
            print "usage: fcrypt.py -d destination_private_key_filename sender_public_key_filename ciphertext_file output_plaintext_file"
            return

        operation = sys.argv[1]
        if operation == '-e':
        #Encryption
            destination_public_key = get_public_key(sys.argv[2])
            sender_private_key = get_private_key(sys.argv[3])
            input_plaintext = get_file_contents(sys.argv[4])
            cipher_text = sys.argv[5]
            perform_encryption(destination_public_key, sender_private_key, input_plaintext, cipher_text)
        elif operation == '-d':
        #Decryption
            destination_private_key = get_private_key(sys.argv[2])
            sender_public_key = get_public_key(sys.argv[3])
            cipher_text = get_file_contents(sys.argv[4])
            output_file = sys.argv[5]
            perform_decryption(destination_private_key, sender_public_key, cipher_text, output_file)
        else:
            print "Please use -e/-d as first argument"
            return
    #
    except Exception, e:
        print "Some error occurred!" % e+"Gracefully exiting from program."

if __name__ == "__main__":
    main()