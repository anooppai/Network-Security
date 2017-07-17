import pickle
import AES
import RSA


#  Client initiates logout
def init_logout_message(sender, server_pub, nonce, dos_cookie):
    # Create a packet with clients ID, a nonce and the dos cookie
    packet = {'sender': sender, 'nonce': str(nonce), 'dos_cookie' : dos_cookie}
    cipher_text = RSA.rsa_encrypt(server_pub, pickle.dumps(packet))
    return cipher_text


# Server verifies the client upon examining the message
def verify_logout_message(cipher_text, server_private):
    # decrypt the message using server private key
    message = RSA.rsa_decrypt(server_private,cipher_text)
    return pickle.loads(message)


# Server decrements the client nonce and sends back a nonce of his own
def server_sends_nonce(nonce1, nonce2, shared_key):
    # Subtract one from nonce1
    nonce1 = int(nonce1)-1
    # Create the packet
    packet = {'nonce1' : str(nonce1), 'nonce2':nonce2 }
    # Encrypt the packet using the shared key
    iv, nonce12, tag = AES.encrypt(pickle.dumps(packet),shared_key)
    return iv, nonce12, tag


# Client checks whether nonce1 was correct and sends back nonce 2 after decrementing it
def client_sends_nonce2(cipher_text, iv, tag, shared_key, expected_nonce1):
    # decrypt the message using shared key between sender and server
    message = AES.decrypt(cipher_text, shared_key, iv, tag)
    packet = pickle.loads(message)
    if str(expected_nonce1) != packet['nonce1']:
        raise ValueError('Incorrect nonce1')
    # Subtract one from nonce2
    nonce2 = int(packet['nonce2'])-1
    # Encrypt the packet using the sender server shared key
    iv, nonce2, tag = AES.encrypt(str(nonce2),shared_key)
    return iv,nonce2,tag


# Server verifies nonce 3
def server_verifies_nonce3(cipher_text, iv, tag, shared_key, expected_nonce2):
    # decrypt the message using shared key between sender and receiver
    message = AES.decrypt(cipher_text, shared_key, iv, tag)
    if str(expected_nonce2) != message:
        return False
    return True


# Server lets all the client know that this user has logged out.
def encrypt_logout_broadcast(user,shared_key):
    iv, cipher, tag = AES.encrypt(user, shared_key)
    return iv,cipher,tag