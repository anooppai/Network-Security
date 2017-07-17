import ConfigParser
import socket
import time
from threading import Thread

import Logout
from MessageExchangeProtocol import *
import NeedhamSchroeder
from Constants import *
from MessageType import *
import RSA
import AES
import random
import os

login_status = {'status': 'INIT'}
list_status = {'status': 'IDLE'}
msg_status_dict = {}
msg_nonces_dict = {}
server_nonces_dict = {}
message_exchange = {}
username_address_dict = {}
key_exchange_dict = {}
user_address_dict = {}
address_user_dict = {}
msg_keys_dict = {}
remote_client = ""
logout_nonce = 0


# DOS solve challenge
def solve_challenge(server_nonce, puzzle):
    for guess in range(0, pow(2, 15)):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(str(server_nonce))
        digest.update(str(guess))
        answer = digest.finalize()
        if answer == puzzle:
            return guess


# Client initiates the login process by sending a packet to server
def init_login(packet, server_public_key_file, g, p, username):
    cookie = packet['cookie']
    puzzle = cookie.puzzle
    server_nonce = packet['server_nonce']
    guess = solve_challenge(server_nonce, puzzle)
    if guess == pow(2, 15):
        raise ValueError('Puzzle not recognized.')

    a = random.getrandbits(8*NONCE_SIZE)
    # Generate client contribution - (k*g^w + g^b mod p) mod p
    contribution = pow(g, a, p)
    encrypted_username = RSA.rsa_encrypt(server_public_key_file, username)
    packet = Packet('INITIATE_LOGIN', {'cookie': cookie, 'puzzle_answer': guess, 'username': encrypted_username,
                                       'contribution': contribution})
    return packet, cookie, a


# Converts password into its hash
def convert_password(g, p, password):
    binary_string = ''.join(format(ord(x), 'b') for x in password)
    number = int(binary_string, 2)
    return pow(g, number, p)


# The response to the challenge sent out by the server is encrypted; new challenge is forwarded
def authenticate_login(packet, g, p, password, secret):
    hashed_password = int(''.join(format(ord(x), 'b') for x in password), 2)
    password_stored = convert_password(g, p, password)
    # Server challenge received
    server_contribution = long(packet['contribution']) - password_stored
    u = packet['nonce']
    power = secret + (u * hashed_password)
    session_key = pow(server_contribution, power, p)
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(str(session_key))
    session_key = digest.finalize()
    # New challenge sent out
    nonce2 = random.getrandbits(8*NONCE_SIZE)
    nonce2_dec = (packet['challenge']-1, nonce2)
    (iv, encrypted_data, tag) = AES.encrypt(pickle.dumps(nonce2_dec), str(session_key))
    packet = Packet('AUTHENTICATION', {'iv': iv, 'data': encrypted_data, 'tag': tag})
    return packet, session_key, nonce2


# Ensure that the server responded to the challenge in the correct way
def authenticate_server(packet, session_key, client_nonce):
    challenge_response = AES.decrypt(packet['data'], session_key, packet['iv'], packet['tag'])
    if long(challenge_response) != (client_nonce - 1):
        raise ValueError('Invalid response from server.')


# Ensure that the time taken by the service is less than the 'max_allowed_time'
def is_invalid(timestamp, max_allowed_time):
    return (time.time() - timestamp) > max_allowed_time


# Handles the login-related functionality
def perform_login(sock, server_address, server_public_key_file, g, p, username, password):
    packet = Packet('LOGIN', {})
    try:
        sock.sendto(pickle.dumps(packet), server_address)
    except:
        print 'Server is not running at the moment!'
        return False
    try:
        # DOS cookie returned from server
        packet, return_server_address = sock.recvfrom(BUFFER_SIZE)
    except:
        print 'Server is not running at the moment!'
        return False
    packet = pickle.loads(packet)

    if packet.type != 'LOGIN_RESPONSE':
        if packet.type == 'ERROR':
            raise ValueError(packet.data['message'])
        else:
            raise ValueError('Sorry! Something went wrong while logging you in.')

    if server_address != return_server_address:
        raise ValueError("Sender's authenticity not verified.")

    # Client-related information is forwarded to server
    (packet, cookie, a) = init_login(packet.data, server_public_key_file, g, p, username)
    try:
        sock.sendto(pickle.dumps(packet), server_address)
    except:
        print 'Server is not running at the moment!'
        return False
    try:
        # Server responds with a nonce, challenge and Diffie-Hellman contribution
        packet, return_server_address = sock.recvfrom(BUFFER_SIZE)
    except:
        print 'Server is not running at the moment!'
        return False
    packet = pickle.loads(packet)

    if packet.type != 'INITIATE_LOGIN_RESPONSE':
        if packet.type == 'ERROR':
            raise ValueError(packet.data['message'])
        else:
            raise ValueError('Sorry! Something went wrong while logging you in.')

    if server_address != return_server_address:
            raise ValueError("Sender's authenticity could not be verified.")

    # Client is authenticated when he generates the shared session key after encrypting the challenge
    (packet, session_key, client_sent_nonce) = authenticate_login(packet.data, g, p, password, a)
    try:
        sock.sendto(pickle.dumps(packet), server_address)
    except:
        print 'Server is not running at the moment!'
        return False
    # Wait till the server is authenticated
    packet, return_server_address = sock.recvfrom(BUFFER_SIZE)
    packet = pickle.loads(packet)
    if server_address != return_server_address:
        if packet.type == 'ERROR':
            raise ValueError(packet.data['message'])
        else:
            raise ValueError("Sender's authenticity could not be verified.")
    if packet.type != 'AUTHENTICATION_COMPLETE':
        if packet.type == 'ERROR':
            raise ValueError(packet.data['message'])
        else:
            raise ValueError('Sorry! Something went wrong while logging you in.')
    authenticate_server(packet.data, session_key, client_sent_nonce)

    # Two-way authentication between client and server has taken place; update status
    global login_status
    login_status = {'status': 'LOGGED_IN', 'session_key': session_key, 'cookie': cookie, 'timestamp': time.time()}
    print 'Hi, ' + username + '. You have logged in. Welcome to SecureChat!'
    return True


# Initiate message for 'list' command
def request_list(cookie, username, server_public_key_file):
    nonce = random.getrandbits(8*NONCE_SIZE)
    data = (username, nonce)
    packet = Packet('INIT_LIST', {'cookie': cookie, 'data': RSA.rsa_encrypt(server_public_key_file, pickle.dumps(data))})
    global list_status
    list_status = {'status': 'INITIATED', 'nonce': nonce-1, 'time': time.time()}
    return packet


# LOGOUT COMMAND
# initiate logout for this user.
def init_logout(sock, server_address, username, server_public_key_file, cookie):
    global logout_nonce
    logout_nonce = random.getrandbits(8*NONCE_SIZE)
    cipher_text = Logout.init_logout_message(username, server_public_key_file, logout_nonce, cookie)
    packet = Packet("INIT_LOGOUT", cipher_text)
    try:
        sock.sendto(pickle.dumps(packet), server_address)
    except:
        print 'Server is not running at the moment!'


def perform_key_exchange(sock, server_address, username, receiver_username, cookie, session_key, server_public_key_file):
    # print 'Connecting to ' + receiver_username + '...'
    # start needham shroeder
    iv, cipher_text, tag = NeedhamSchroeder.send_init_message(username, receiver_username, cookie, server_public_key_file, session_key)
    packet = Packet('INIT', {'cipher_text': cipher_text, 'iv': iv, 'tag': tag})
    try:
        sock.sendto(pickle.dumps(packet), server_address)
    except:
        print 'Server is not running at the moment!'
    msg_status_dict[receiver_username] = 'INIT'
    global remote_client
    remote_client = receiver_username


# Encrypt and send message to client.
def send_message(sock, receiver_address, message):
    if receiver_address in message_exchange and type(message_exchange[receiver_address]) is MessageExchangeProtocol:
        message_class = message_exchange[receiver_address]
        iv, cipher_text, tag = message_class.send_message(message)
        packet = Packet('MESSAGE', {'iv': iv, 'cipher_text': cipher_text, 'tag': tag})
        try:
            sock.sendto(pickle.dumps(packet), receiver_address)
        except:
            print 'Server is not running at the moment!'


def list_handler(sock, username, server_public_key_file, server_address):
    if login_status['status'] != 'LOGGED_IN':
        print 'You have not logged in.'
    else:
        # send request to server, iff a request has not been sent earlier.
        if list_status['status'] == 'INITIATED':
            print 'Server is not running at the moment!'
        elif list_status['status'] == 'IDLE':
            packet = request_list(login_status['cookie'], username, server_public_key_file)
            try:
                sock.sendto(pickle.dumps(packet), server_address)
            except:
                print 'Server is not running at the moment!'


def send_handler(sock, message, username, receiver_username, server_public_key_file, server_address, g, p):
    global message_exchange
    time_passed = 0
    if not (receiver_username in username_address_dict and username_address_dict[
        receiver_username] in message_exchange and type(
            message_exchange[username_address_dict[receiver_username]]) is MessageExchangeProtocol):
        perform_key_exchange(sock, server_address, username, receiver_username, login_status['cookie'],
                             login_status['session_key'], server_public_key_file)
        current_time = time.time()
        while True:
            time_passed = time.time() - current_time
            if time_passed > 3 or (receiver_username in username_address_dict and username_address_dict[
                receiver_username] in message_exchange and type(
                    message_exchange[username_address_dict[receiver_username]]) is MessageExchangeProtocol):
                break
    if not time_passed > 3:
        send_message(sock, username_address_dict[receiver_username], message)


# Handle user commands
def user_commands(sock, server_address, server_public_key_file, g, p, username):
    while True:
        try:
            command = raw_input()
            tokens = command.split(' ')
            if command == 'list':
                list_handler(sock, username, server_public_key_file, server_address)
            elif tokens[0] == 'send':
                receiver_username = tokens[1]
                # send message to another client.
                message = ' '.join(tokens[2:])
                if receiver_username == username:
                    print 'Sorry, you cannot send yourself a message.'
                    continue
                send_handler(sock, message, username, receiver_username, server_public_key_file, server_address, g, p)
            elif command == 'logout':
                init_logout(sock, server_address, username, server_public_key_file,login_status['cookie'])
            else:
                print 'Invalid command'
        except ValueError as error:
            print 'Error: %s' % error
        except Exception, e:
            print 'Something went wrong. Please try again.'


# Performs initial key exchange for client-to-client communication
def c2c_init_key_exchange(connection, packet, sender_address, g, p, username):
    global username_address_dict
    global key_exchange_dict
    global message_exchange
    sender = key_exchange_dict[sender_address]
    data = AES.decrypt(packet['cipher_text'], sender.shared_key, packet['iv'], packet['tag'])
    data = pickle.loads(data)
    sender_username = data['username']
    if sender.username != sender_username:
        raise ValueError('Remote client could not be authenticated.')
    sender_dh_contribution = data['contribution']
    sender_sequence_number = data['sequence_number']
    sender_nonce = data['nonce']
    # Generate Diffie-Hellman Private Key
    dh_key = random.getrandbits(8*DH_SIZE)
    # Generate Diffie-Hellman contribution
    dh_contribution = pow(g, dh_key, p)
    nonce = random.getrandbits(8*NONCE_SIZE)
    sequence_number = random.getrandbits(8*SEQ_SIZE)
    data = {'username': username, 'nonce': nonce, 'contribution': dh_contribution, 'sequence_number': sequence_number}
    # Perform AES Encryption when sending out username, DH contribution and nonce used
    iv, cipher_text, tag = AES.encrypt(pickle.dumps(data), sender.shared_key)
    packet = Packet('INIT_KEY_EXCHANGE_RESPONSE', {'iv': iv, 'cipher_text': cipher_text, 'tag': tag})
    connection.sendto(pickle.dumps(packet), sender_address)
    shared_message_key = str(pow(sender_dh_contribution, dh_key, p)) + str(nonce) + str(sender_nonce)
    message_exchange[sender_address] = MessageExchangeProtocol(username, sender_username, sequence_number,
                                                               sender_sequence_number, 2, 1, shared_message_key)


# Receives message from server
def c2c_receive_key_message(packet, sender_address, p, username):
    if sender_address not in message_exchange or not type(message_exchange[sender_address]) is InitMessageExchange:
        raise ValueError('Something went wrong. Please Try again.')
    sender = key_exchange_dict[sender_address]
    init_message = message_exchange[sender_address]
    data = AES.decrypt(packet['cipher_text'], sender.shared_key, packet['iv'], packet['tag'])
    data = pickle.loads(data)
    sender_username = data['username']
    if sender.username != sender_username:
        raise ValueError('Remote client could not be authenticated.')
    sender_dh_contribution = data['contribution']
    sender_nonce = data['nonce']
    sender_sequence_number = data['sequence_number']
    shared_message_key = str(pow(sender_dh_contribution, init_message.secret, p)) + str(sender_nonce) + str(init_message.nonce)
    message_exchange[sender_address] = MessageExchangeProtocol(username, sender_username, init_message.sequence_number, sender_sequence_number, 1, 2, shared_message_key)


# CLIENT - CLIENT INITIAL KEY EXCHANGE
def init_key_exchange(sock, receiver_username, g, p, username):
    global username_address_dict
    global key_exchange_dict
    global message_exchange
    if receiver_username not in username_address_dict:
        raise ValueError('Remote client could not be authenticated.')
    receiver_address = username_address_dict[receiver_username]
    if receiver_address not in key_exchange_dict or not type(key_exchange_dict[receiver_address]) is KeyExchange:
        raise ValueError('Remote client could not be authenticated.')
    receiver = key_exchange_dict[receiver_address]
    # create DH private key
    dh_key = random.getrandbits(8*DH_SIZE)
    # create DH contribution
    dh_contribution = pow(g, dh_key, p)
    # generate a nonce
    nonce = random.getrandbits(8*NONCE_SIZE)
    # generate a sequence number
    sequence_number = random.getrandbits(8*SEQ_SIZE)
    data = {'username': username, 'nonce': nonce, 'contribution': dh_contribution, 'sequence_number': sequence_number}
    # encrypt sender's username, nonce and DH contribution using aes gcm mode
    iv, cipher_text, tag = AES.encrypt(pickle.dumps(data), receiver.shared_key)
    packet = Packet('INIT_KEY_EXCHANGE', {'iv': iv, 'cipher_text': cipher_text, 'tag': tag})
    try:
        sock.sendto(pickle.dumps(packet), receiver_address)
    except:
        print 'Receiver not connected at the moment!'
    message_exchange[receiver_address] = InitMessageExchange(dh_key, nonce, sequence_number, time.time())


# Use challenge-response mechanism to authenticate with server
def authenticate_list(packet, session_key):
    global list_status
    # Verify if the client has already initiated a list command
    if list_status['status'] != 'INITIATED' or is_invalid(list_status['time'], LIST_THRESHOLD):
        list_status = {'status': 'IDLE'}
        raise ValueError('Sorry! A problem was encountered with "list". Please try later.')

    # Verify server's response
    challenge_response, challenge = pickle.loads(AES.decrypt(packet['data'], session_key, packet['iv'], packet['tag']))
    if challenge_response != list_status['nonce']:
        list_status = {'status': 'IDLE'}
        raise ValueError('Sorry! A problem was encountered with "list". Please try later.')

    # Respond with a response to server's challenge
    server_nonce = challenge - 1
    (iv, cipher_text, tag) = AES.encrypt(pickle.dumps(server_nonce), session_key)
    packet = Packet('LIST_AUTHENTICATION', {'iv': iv, 'data': cipher_text, 'tag': tag})
    list_status = {'status': 'LIST_AUTHENTICATION', 'time': time.time()}
    return packet


# Prints the list of users logged in
def list_users(packet, session_key):
    global list_status
    if list_status['status'] != 'LIST_AUTHENTICATION' or is_invalid(list_status['time'], LIST_THRESHOLD):
        list_status = {'status': 'IDLE'}
        raise ValueError('Sorry! A problem was encountered with "list". Please try later.')

    # Retrieve the list of online users
    online_clients = pickle.loads(AES.decrypt(packet['data'], session_key, packet['iv'], packet['tag']))
    list_status = {'status': 'IDLE'}
    print '=====List of online clients======'
    for client_username in online_clients:
        print client_username
    print '================================='


# Client initiates a conversation with the receiver
def initiate_talk_to_receiver(decrypted_message, sock):
    packet = Packet('INIT_RECEIVER', {'sender_receiver_encrypted': decrypted_message['sender_receiver_encrypted'],
                                     'iv': decrypted_message['iv'], 'tag':decrypted_message['tag']})
    try:
        sock.sendto(pickle.dumps(packet), decrypted_message['receiver_address'])
    except:
        print 'Receiver not connected at the moment!'
    user_address_dict[decrypted_message['receiver']] = decrypted_message['receiver_address']
    address_user_dict[decrypted_message['receiver_address']] = decrypted_message['receiver']
    msg_status_dict[decrypted_message['receiver']] = 'INIT_RECEIVER'


# Clearing all sessions of logged out user, associated with current client.
def logout(user):
    user_address = user_address_dict[user]
    if user in server_nonces_dict:
        del server_nonces_dict[user]
    if user in msg_keys_dict:
        del msg_keys_dict[user]
    if user in username_address_dict:
        del username_address_dict[user]
    if user in msg_status_dict:
        del msg_status_dict[user]
    if user in msg_nonces_dict:
        del msg_nonces_dict[user]
    if user_address in address_user_dict:
        del address_user_dict[user_address]
    if user_address in key_exchange_dict:
        del key_exchange_dict[user_address]
    if user_address in message_exchange:
        del message_exchange[user_address]
    if user in user_address_dict:
        del user_address_dict[user]


# Receiver decrypts sender's message and sends a nonce
def receiver_verify_sender(sock, packet, sender_address):
    # Decrypt the message and send back a nonce
    decrypted_packet = NeedhamSchroeder.receiver_init_decrypt(packet.data['sender_receiver_encrypted'],
                                                              packet.data['iv'], packet.data['tag'],
                                                              login_status['session_key'])
    global remote_client
    remote_client = decrypted_packet['sender']
    user_address_dict[decrypted_packet['sender']] = sender_address
    address_user_dict[sender_address] = decrypted_packet['sender']
    nonce = random.getrandbits(8 * NONCE_SIZE)
    msg_nonces_dict[decrypted_packet['sender']] = nonce
    msg_status_dict[decrypted_packet['sender']] = 'INIT_RECEIVER_RESPONSE'
    iv, cipher_text, tag = NeedhamSchroeder.receiver_init_message(decrypted_packet['sender'], nonce,
                                                                  login_status['session_key'])
    pack = Packet("INIT_RECEIVER_RESPONSE", {"iv": iv, "cipher_text": cipher_text, "tag": tag})
    try:
        sock.sendto(pickle.dumps(pack), sender_address)
    except:
        print 'Receiver not connected at the moment!'


# Sender requests a ticket to initiate talk to receiver
def request_ticket(sock, packet, sender_address, username, server_address):
    sender = address_user_dict[sender_address]
    msg_status_dict[sender] = "FETCHING_TICKET"
    iv, sender_receiver_encrypted, tag = NeedhamSchroeder.sender_server_message(username, sender,
                                                                                login_status[
                                                                                    'session_key'])
    server_nonces_dict[sender] = random.getrandbits(8 * NONCE_SIZE)
    pack = Packet("FETCHING_TICKET", {"nonce": server_nonces_dict[sender],
                                      "sender_receiver_encrypted": sender_receiver_encrypted,
                                      "encrypted_from_receiver": packet.data, "iv": iv, "tag": tag})
    try:
        sock.sendto(pickle.dumps(pack), server_address)
    except:
        print 'Server is not running at the moment!'


# Receiver sends decremented nonce2 and a new nonce3
def receiver_verifies_sends_nonces(sock, packet):
    # Decrypt the ticket and the nonce
    enc_ticket = packet.data['ticket']
    decrypted_ticket = NeedhamSchroeder.get_decrypted_message(enc_ticket['ticket'], enc_ticket['iv'],
                                                              enc_ticket['tag'],
                                                              login_status['session_key'])
    decrypted_ticket = pickle.loads(decrypted_ticket)
    if decrypted_ticket['nonce'] != msg_nonces_dict[decrypted_ticket['sender']]:
        print "Invalid Nonce."
    else:
        msg_keys_dict[decrypted_ticket['sender']] = decrypted_ticket['sender_receiver_key']
        decrypted_nonce = NeedhamSchroeder.get_decrypted_message(packet.data['nonce2'], packet.data['iv'],
                                                                 packet.data['tag'],
                                                                 msg_keys_dict[decrypted_ticket['sender']])
        nonce2 = int(decrypted_nonce)
        nonce3 = str(random.getrandbits(8 * NONCE_SIZE))
        msg_nonces_dict[decrypted_ticket['sender']] = nonce3
        iv, nonce23, tag = NeedhamSchroeder.receiver_nonce3_sender(nonce2, nonce3,
                                                                   msg_keys_dict[decrypted_ticket['sender']])
        pack = Packet("NONCE_2-3", {"iv": iv, "nonce23": nonce23, "tag": tag})
        msg_status_dict[decrypted_ticket['sender']] = "NONCE_2-3"
        try:
            sock.sendto(pickle.dumps(pack), user_address_dict[decrypted_ticket['sender']])
        except:
            print 'Receiver is not connected at the moment!'


# Sender verifies nonce2 and sends decremented nonce3 to receiver
def sender_verifies_sends_nonces(sender_address, packet, sock, g, p, username):
    sender = address_user_dict[sender_address]
    expected_nonce2 = str(int(msg_nonces_dict[sender]) - 1)
    iv, nonce3, tag = NeedhamSchroeder.sender_updates_nonce3(packet.data['nonce23'], packet.data['iv'],
                                                             packet.data['tag'],
                                                             msg_keys_dict[sender], expected_nonce2)
    if iv is False:
        print "Nonce 2 is not as expected"
    else:
        pack = Packet("NONCE_3", {"iv": iv, "nonce3": nonce3, "tag": tag})
        msg_status_dict[sender] = "SESSION_VERIFIED"
        try:
            sock.sendto(pickle.dumps(pack), sender_address)
        except:
            print 'Receiver is not connected at the moment!'
        receiver_address = user_address_dict[sender]
        global key_exchange_dict
        key_exchange_dict[receiver_address] = KeyExchange(key_exchange_dict[receiver_address].username,
                                                          key_exchange_dict[receiver_address].shared_key,
                                                          key_exchange_dict[receiver_address].timestamp)
        global username_address_dict
        username_address_dict[key_exchange_dict[receiver_address].username] = receiver_address
        init_key_exchange(sock, key_exchange_dict[receiver_address].username, g, p, username)


# Receiver verifies nonce3
def receiver_verifies_nonce3(sender_address, packet):
    sender = address_user_dict[sender_address]
    expected_nonce3 = str(int(msg_nonces_dict[sender]) - 1)
    key = NeedhamSchroeder.receiver_nonce3_verifier(packet.data['nonce3'], packet.data['iv'],
                                                    packet.data['tag'],
                                                    msg_keys_dict[sender], expected_nonce3)
    if key is False:
        print "Nonce 3 is not as expected"
    else:
        msg_status_dict[sender] = "SESSION_VERIFIED"
        key_exchange_dict[sender_address] = KeyExchange(sender, msg_keys_dict[sender], time.time())
        username_address_dict[key_exchange_dict[sender_address].username] = sender_address


# Sender checks authenticity of server
def sender_verify_init(packet, sock):
    # Check server reply here
    decrypted_packet = NeedhamSchroeder.verify_server_reply_to_init(packet.data['cipher_text'],
                                                                    packet.data['iv'],
                                                                    packet.data['tag'],
                                                                    login_status['session_key'],
                                                                    remote_client)
    if decrypted_packet:
        initiate_talk_to_receiver(decrypted_packet, sock)
    else:
        print "Receiver changed or not as expected"


# Sender sends ticket to receiver with a new nonce
def sender_sends_ticket_to_receiver(sock, packet):
    # Check if ticket is valid by checking the Nonce
    decrypted_packet = NeedhamSchroeder.get_decrypted_message(packet.data['cipher_text'],
                                                              packet.data['iv'], packet.data['tag'],
                                                              login_status['session_key'])
    decrypted_packet = pickle.loads(decrypted_packet)
    packet = NeedhamSchroeder.sender_ticket_verifier(packet.data['cipher_text'], packet.data['iv'],
                                                   packet.data['tag'],
                                                   login_status['session_key'],
                                                   decrypted_packet['receiver'],
                                                   server_nonces_dict[decrypted_packet['receiver']])
    if not packet:
        print "Ticket has been fabricated."
    else:
        msg_keys_dict[decrypted_packet['receiver']] = decrypted_packet['sender_receiver_key']
        key_exchange_dict[user_address_dict[decrypted_packet['receiver']]] = InitKeyExchange(
            decrypted_packet['receiver'],
            decrypted_packet[
                'sender_receiver_key'], time.time())
        nonce2 = str(random.getrandbits(8 * NONCE_SIZE))
        msg_nonces_dict[decrypted_packet['receiver']] = nonce2
        iv, enc_nonce2, tag = NeedhamSchroeder.sender_ticket_to_receiver(nonce2, decrypted_packet[
            'sender_receiver_key'])
        sending_packet = Packet("SEND_TICKET",
                                {"ticket": decrypted_packet['ticket'], "nonce2": enc_nonce2,
                                 "iv": iv, "tag": tag})
        try:
            sock.sendto(pickle.dumps(sending_packet), user_address_dict[decrypted_packet['receiver']])
        except:
            print 'Receiver is not connected at the moment!'


# Handles logout
def logout_handler(packet, sock, server_address, username):
    if packet.type == "LOGOUT_RESPONSE":
        try:
            iv, cipher_text, tag = Logout.client_sends_nonce2(packet.data['cipher_text'], packet.data['iv'],
                                                              packet.data['tag'],
                                                              login_status['session_key'], logout_nonce - 1)
            logout_packet = Packet("VERIFY_LOGOUT", {"iv": iv, "cipher_text": cipher_text, "tag": tag})
            try:
                sock.sendto(pickle.dumps(logout_packet), server_address)
            except:
                print 'Receiver is not connected at the moment!'
        except:
            print "Nonce 1 is not as expected"
    elif packet.type == "PERFORM_LOGOUT":
        user = NeedhamSchroeder.get_decrypted_message(packet.data['cipher_text'], packet.data['iv'],
                                                      packet.data['tag'],
                                                      login_status['session_key'])
        print user + " has just logged out!"
        logout(user)
    elif packet.type == "LOGGING_OUT":
        user = NeedhamSchroeder.get_decrypted_message(packet.data['cipher_text'], packet.data['iv'],
                                                      packet.data['tag'],
                                                      login_status['session_key'])
        if user == username:
            os._exit(0)


# Responsible for handling all client-client communication
def receive_msg_sock(sock, server_address, session_key, username, g, p):
    while True:
        try:
            packet, sender_address = sock.recvfrom(BUFFER_SIZE)
        except:
            print "Server is not running at the moment!"
            continue
        packet = pickle.loads(packet)
        if packet.type == 'INIT_KEY_EXCHANGE':
            c2c_init_key_exchange(sock, packet.data, sender_address, g, p, username)
        elif packet.type == 'INIT_KEY_EXCHANGE_RESPONSE':
            c2c_receive_key_message(packet.data, sender_address, p, username)
        elif packet.type == "SERVER_INIT_RESPONSE":
            sender_verify_init(packet, sock)
        elif packet.type == "INIT_RECEIVER":
            receiver_verify_sender(sock, packet, sender_address)
        elif packet.type == "INIT_RECEIVER_RESPONSE":
            request_ticket(sock, packet, sender_address, username, server_address)
        elif packet.type == "TICKET":
            sender_sends_ticket_to_receiver(sock, packet)
        elif packet.type == "SEND_TICKET":
            receiver_verifies_sends_nonces(sock, packet)
        elif packet.type == "NONCE_2-3":
            sender_verifies_sends_nonces(sender_address, packet, sock, g, p, username)
        elif packet.type == "NONCE_3":
            receiver_verifies_nonce3(sender_address, packet)
        elif packet.type == 'MESSAGE':
            print message_exchange[sender_address].receive_message(packet.data['cipher_text'], packet.data['iv'], packet.data['tag'])
        elif packet.type == 'INIT_LIST_RESPONSE':
            packet = authenticate_list(packet.data, session_key)
            try:
                sock.sendto(pickle.dumps(packet), sender_address)
            except:
                print 'Server is not running at the moment!'
        elif packet.type == 'LIST_AUTHENTICATED':
            list_users(packet.data, session_key)
        elif packet.type == "LOGOUT_RESPONSE" or packet.type == "PERFORM_LOGOUT" or packet.type == "LOGGING_OUT":
            logout_handler(packet, sock, server_address, username)
        else:
            if sender_address != server_address:
                raise ValueError('Server has been impersonated.')
            elif packet.type == "ERROR":
                print packet.data['message']
            else:
                raise ValueError('Something went wrong. Please try again.')


def main():
    # Client configuration is read from the .cfg file
    config = ConfigParser.RawConfigParser()
    config.read(client_cfg_filename)
    server_public_key_file = config.get('server_keys', 'public_key')
    g = config.getint('DH_config', 'g')
    p = long(config.get('DH_config', 'p'), 16)
    server_address = (config.get('server_address', 'ip_address'), config.getint('server_address', 'port'))

    # Socket communication
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    while True:
        try:
            print 'Login'
            username = raw_input('Enter username: ')
            password = raw_input('Enter password: ')
            if login_status['status'] != 'INIT':
                login_status['status'] = 'INIT'
            # Perform login operation
            logged_in = perform_login(client_socket, server_address, server_public_key_file, g, p, username, password)
            if not logged_in:
                continue
            # Client-to-client communication is multi-threaded; both when it receives and sends messages
            Thread(target=receive_msg_sock, args=(client_socket, server_address, login_status['session_key'], username, g, p)).start()
            Thread(target=user_commands, args=(client_socket, server_address, server_public_key_file, g, p, username)).start()
            break
        except ValueError as error:
            print '%s' % error

if __name__ == "__main__":
    main()
