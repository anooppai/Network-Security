Python version : 2.7.12

fcrpyt.py is a python application that performs encryption and decryption by combining both symmetric and asymmetric encryption methods. In my program, I have used AES encryption to perform plain-text encryption, and RSA encryption to encrypt the shared session key.

This application works for only those destination public/private keys generated that have an extension of .der

This script has been tested successfully for plain-text files, binary files and also image files.

In order to run this python application, follow the below commands for encryption and decryption respectively : 

python fcrypt.py -e destination_public_key_filename sender_private_key_filename input_plaintext_file ciphertext_file


python fcrypt.py -d destination_private_key_filename sender_public_key_filename ciphertext_file output_plaintext_file


