import pickle
import AES
import RSA


#  A requests server that he wants to talk to B
def send_init_message(sender, receiver, dos_cookie, server_public_key, shared_key):
    encrypted_receiver = RSA.rsa_encrypt(server_public_key, receiver)
    # New packet created containing the sender, encrypted receiver and dos cookie
    packet = {'sender': sender, 'encrypted_receiver': encrypted_receiver, 'dos_cookie': dos_cookie}
    iv, cipher_text, tag = AES.encrypt(pickle.dumps(packet), shared_key)
    return iv, cipher_text, tag


# Server checks if it was actually A who sent the message
def verify_init_message(packet, server_private_key, shared_key, cookie):
    decrypted_packet = AES.decrypt(packet['cipher_text'], shared_key, packet['iv'], packet['tag'])
    decrypted_packet = pickle.loads(decrypted_packet)
    receiver = RSA.rsa_decrypt(server_private_key, decrypted_packet['encrypted_receiver'])
    # Throw an error in the event when the cookies mismatch
    if str(cookie) != str(decrypted_packet['dos_cookie']):
        raise ValueError("Cookies are not same")
    return receiver, decrypted_packet['sender']


# Server replies to A with receivers information
def server_reply_to_init(receiver_address, receiver, sender, receiver_shared_key, sender_shared_key):
    sender_receiver = {'sender': sender, 'receiver': receiver}
    iv, sender_receiver_encrypted, tag = AES.encrypt(pickle.dumps(sender_receiver), receiver_shared_key)
    packet = {'receiver_address': receiver_address, 'receiver': receiver, 'iv': iv,
              'sender_receiver_encrypted': sender_receiver_encrypted, 'tag': tag}
    # Created packet is encrypted with sender and the key that is shared between the two entities
    iv, cipher_text, tag = AES.encrypt(pickle.dumps(packet), sender_shared_key)
    return iv, cipher_text, tag


# A checks if it was actually the server who sent the reply
def verify_server_reply_to_init(cipher_text, iv, tag, shared_key, expected_receiver_name):
    message = AES.decrypt(cipher_text, shared_key, iv, tag)
    packet = pickle.loads(message)
    # Throw an error in the event when the receiver names mismatch
    if expected_receiver_name != packet['receiver']:
        return False
    return packet


# B decrypts this message using his shared key with server
def receiver_init_decrypt(cipher_text, iv, tag, receiver_shared_key):
    message = AES.decrypt(cipher_text, receiver_shared_key, iv, tag)
    packet = pickle.loads(message)
    return packet


# B sends his reply to A to confirm communication
def receiver_init_message(sender, nonce, receiver_shared_key):
    receiver_nonce = {'sender': sender, 'nonce': nonce}
    iv, cipher_text, tag = AES.encrypt(pickle.dumps(receiver_nonce), receiver_shared_key)
    return iv, cipher_text, tag


# A sends server a message to get the ticket to talk to B
def sender_server_message(sender, receiver, sender_shared_key):
    sender_receiver = {'sender': sender, 'receiver': receiver}
    iv, sender_receiver_encrypted, tag = AES.encrypt(pickle.dumps(sender_receiver), sender_shared_key)
    return iv, sender_receiver_encrypted, tag


# Server creates ticket so that A could talk to B
def ticket_creator(sender, receiver, nonce, sender_receiver_key, receiver_shared_key):
    packet = {'sender': sender, 'receiver': receiver, 'nonce': nonce, 'sender_receiver_key': sender_receiver_key}
    iv, ticket, tag = AES.encrypt(pickle.dumps(packet), receiver_shared_key)
    return iv, ticket, tag


# Server sends A Ticket to talk to B
def ticket_issuer(sender_nonce, receiver, sender_receiver_key, ticket, sender_shared_key):
    packet = {'sender_nonce': sender_nonce, 'receiver': receiver, 'sender_receiver_key': sender_receiver_key,
              'ticket': ticket}
    iv, cipher_text, tag = AES.encrypt(pickle.dumps(packet), sender_shared_key)
    return iv, cipher_text, tag


# A checks the packet from server for nonce he had sent
def sender_ticket_verifier(cipher_text, iv, tag, sender_shared_key, expected_receiver_name, expected_nonce):
    message = AES.decrypt(cipher_text, sender_shared_key, iv, tag)
    packet = pickle.loads(message)
    # Throw an error in the event when the receiver names mismatch
    if expected_receiver_name != packet['receiver']:
        return False
    # Throw an error in the event when the nonces mismatch
    if expected_nonce != packet['sender_nonce']:
        return False
    return packet


# A sends the ticket with a new nonce to B
def sender_ticket_to_receiver(nonce, sender_receiver_key):
    iv, nonce2, tag = AES.encrypt(nonce, sender_receiver_key)
    return iv, nonce2, tag


# B subtracts 1 from nonce2 and sends A his own nonce3
def receiver_nonce3_sender(nonce2, nonce3, sender_receiver_key):
    nonce2 = nonce2 - 1
    packet = {'nonce2': str(nonce2), 'nonce3': nonce3}
    iv, nonce23, tag = AES.encrypt(pickle.dumps(packet), sender_receiver_key)
    return iv, nonce23, tag


# A sends decremented nonce3 to B if nonce 2 was successfully verified
def sender_updates_nonce3(cipher_text, iv, tag, sender_receiver_key, expected_nonce2):
    message = AES.decrypt(cipher_text, sender_receiver_key, iv, tag)
    packet = pickle.loads(message)
    if expected_nonce2 != packet['nonce2']:
        return False
    nonce3 = int(packet['nonce3']) - 1
    iv, nonce3, tag = AES.encrypt(str(nonce3), sender_receiver_key)
    return iv, nonce3, tag


# B checks if nonce3 was returned correctly
def receiver_nonce3_verifier(cipher_text, iv, tag, sender_receiver_key, expected_nonce3):
    message = AES.decrypt(cipher_text, sender_receiver_key, iv, tag)
    if expected_nonce3 != message:
        return False
    return sender_receiver_key


# Performs decryption using AES
def get_decrypted_message(cipher_text, iv, tag, key):
    message = AES.decrypt(cipher_text, key, iv, tag)
    return message
