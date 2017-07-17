import ConfigParser
import os
import pickle
import random
import socket
import sys
import time
from threading import Thread

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

import Logout
import AES
import NeedhamSchroeder
from Constants import *
from MessageType import *
import RSA

user_logout_nonces = {}
user_list_status_dict = {}
user_address_dict = {}
user_login_info_dict = {}
online_users_dict = {}
public_key_file = ""
private_key_file = ""


# Receive login request from client
def receive_login_request(sock, client_address):
    nonce1 = os.urandom(NONCE_SIZE)
    nonce2 = random.getrandbits(15)  # client puzzle
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(str(nonce1))
    digest.update(str(nonce2))
    client_puzzle_hash = digest.finalize()
    # Creates cookie for client containing a challenge
    dos_cookie = Cookie(client_address, time.time(), client_puzzle_hash)
    # Send dos cookie to client
    packet = Packet('LOGIN_RESPONSE', {'cookie': dos_cookie, 'server_nonce': nonce1})
    sock.sendto(pickle.dumps(packet), client_address)
    user_login_info_dict[client_address] = LoginInit(dos_cookie, nonce2)


# Initiates the login process once the server receives a reply from client
def init_login(sock, client_address, packet, stored_passwords, g, p):
    # Verify that this client has already put in a login request as stated in the previous step
    if (client_address not in user_login_info_dict) or (not type(user_login_info_dict[client_address]) is LoginInit):
        raise ValueError('There is no such user.')
    client = user_login_info_dict[client_address]
    # Verify the answer to the puzzle to validate the client
    if client.puzzle_answer != packet['puzzle_answer']:
        del user_login_info_dict[client_address]
        raise ValueError('Unable to Authenticate.')
    # In the event of a cookie mismatch, throw an error
    if str(packet['cookie']) != str(client.cookie):
        raise ValueError('Invalid cookie.')

    client_username = RSA.rsa_decrypt(private_key_file, packet['username'])
    # Raise an error if user has already logged in another session
    if client_username in user_address_dict:
        raise ValueError('User already logged in.')

    client_contribution = long(packet['contribution'])

    # Generate Diffie-Hellman Private Key
    b = random.getrandbits(8 * NONCE_SIZE)

    # Throw an error if client does not exists in the dictionary
    if client_username not in stored_passwords:
        raise ValueError('There is no such user.')

    stored_client_password = long(stored_passwords[client_username])
    # Generate Server contribution - (g^w + g^b mod p) mod p (S.R.P Protocol)
    contribution = (stored_client_password + pow(g, b, p)) % p
    # Generate nonce u
    u = random.getrandbits(8 * NONCE_SIZE)
    challenge = random.getrandbits(8 * NONCE_SIZE)

    # Delivers the packet to client
    packet = Packet('INITIATE_LOGIN_RESPONSE', {'contribution': contribution, 'nonce': u, 'challenge': challenge})
    sock.sendto(pickle.dumps(packet), client_address)
    # Generate session key -  g^b(a+uW) mod p
    session_key = (pow(client_contribution, b, p) * pow(stored_client_password, u * b, p)) % p
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(str(session_key))
    session_key = digest.finalize()
    user_login_info_dict[client_address] = LoginKeyExchange(client.cookie, client_username, session_key,
                                                            time.time(), challenge - 1)


# Mutually authenticates client and server after verifying challenge-responses
def authenticate_login(sock, client_address, packet):
    if (client_address not in user_login_info_dict) or (not type(user_login_info_dict[client_address]) is LoginKeyExchange):
        raise ValueError('There is no such user.')

    user = user_login_info_dict[client_address]
    # Check sender's source address
    if user.cookie.client_address != client_address:
        raise ValueError("Invalid Cookie.")

    challenges = AES.decrypt(packet['data'], user.session_key, packet['iv'], packet['tag'])

    # Condition to check if the nonce sent from the client was decremented, raise an error otherwise.
    challenge_response, challenge = pickle.loads(challenges)
    if challenge_response != user.expected_client_nonce:
        del user_login_info_dict[client_address]
        raise ValueError('Unable to Authenticate.')

    # Upon verification, send a challenge encrypted with the session key
    iv, encrypted_challenge, tag = AES.encrypt(str(challenge - 1), user.session_key)
    packet = Packet('AUTHENTICATION_COMPLETE', {'iv': iv, 'data': encrypted_challenge, 'tag': tag})
    sock.sendto(pickle.dumps(packet), client_address)

    # Make changes to user_status accordingly
    user_login_info_dict[client_address] = LoggedUser(user.cookie, user.client_username,
                                                      user.session_key, time.time())
    user_address_dict[user.client_username] = client_address
    

# Handles login-related functionality
def login_handler(packet, sock, stored_passwords, client_address, g, p):
    try:
        if packet.type == 'LOGIN':
            receive_login_request(sock, client_address)
        elif packet.type == 'INITIATE_LOGIN':
            init_login(sock, client_address, packet.data, stored_passwords, g, p)
        elif packet.type == 'AUTHENTICATION':
            authenticate_login(sock, client_address, packet.data)
    except ValueError, error:
        packet = Packet('ERROR', {'message': str(error)})
        sock.sendto(pickle.dumps(packet), client_address)
        # Delete the user in the event when something goes wrong during login
        if client_address in user_login_info_dict:
            del user_login_info_dict[client_address]
    except:
        packet = Packet('ERROR', {'message': 'Login Failure. Please try again.'})
        sock.sendto(pickle.dumps(packet), client_address)
        if client_address in user_login_info_dict:
            del user_login_info_dict[client_address]


# List Functionality
# After solving the challenge sent by the client, the server sends its own challenge
def init_list(sock, packet, client_address):
    client_username, nonce = pickle.loads(RSA.rsa_decrypt(private_key_file, packet['data']))
    if client_address not in user_login_info_dict or type(user_login_info_dict[client_address]) != LoggedUser:
        raise ValueError('There is no such user.')
    if client_username not in user_address_dict or user_address_dict[client_username] != client_address:
        raise ValueError('Unable to Authenticate.')
    user = user_login_info_dict[client_address]
    if str(packet['cookie']) != str(user.cookie):
        raise ValueError('Invalid Cookie.')

    challenge_response = nonce - 1
    challenge = random.getrandbits(8 * NONCE_SIZE)
    data = (challenge_response, challenge)
    (iv, encrypted_data, tag) = AES.encrypt(pickle.dumps(data), user.session_key)
    packet = Packet('INIT_LIST_RESPONSE', {'iv': iv, 'data': encrypted_data, 'tag': tag})
    # Delivers challenge response to client
    sock.sendto(pickle.dumps(packet), client_address)
    user_list_status_dict[client_address] = ListInit(challenge - 1, time.time())


# Ensure that the time taken by the service is less than the 'max_allowed_time'
def is_invalid(timestamp, max_allowed_time):
    return (time.time() - timestamp) > max_allowed_time


# Server verifies the nonce received from the client. Also, creates a list of online users; sends to client.
def authenticate_list(sock, packet, client_address):
    if client_address not in user_login_info_dict or type(user_login_info_dict[client_address]) != LoggedUser:
        raise ValueError('There is no such User.')
    user = user_login_info_dict[client_address]
    if str(client_address) != str(user.cookie.client_address):
        raise ValueError('Invalid Client.')
    if client_address not in user_list_status_dict or not type(user_list_status_dict[client_address]) is ListInit:
        raise ValueError('Something went wrong! Please try again.')
    # Deletes entry from dictionary if it took longer than desired time frame
    if is_invalid(user_list_status_dict[client_address].timestamp, 100):
        del user_list_status_dict[client_address]
        raise ValueError('It is taking longer than expected. Please try again later.')

    # Challenge response authentication
    challenge_response = pickle.loads(AES.decrypt(packet['data'], user.session_key, packet['iv'], packet['tag']))
    if challenge_response != user_list_status_dict[client_address].expected_client_nonce:
        del user_list_status_dict[client_address]
        raise ValueError('Unable to authenticate.')

    # Creates a list of all online users
    online_clients_list = []
    for client in user_login_info_dict:
        if type(user_login_info_dict[client]) is LoggedUser:
            online_clients_list.append(user_login_info_dict[client].username)

    # Sends the created list to the client
    iv, encrypted_data, tag = AES.encrypt(pickle.dumps(online_clients_list), user.session_key)
    packet = Packet('LIST_AUTHENTICATED', {'iv': iv, 'data': encrypted_data, 'tag': tag})
    sock.sendto(pickle.dumps(packet), client_address)
    del user_list_status_dict[client_address]


# Handles all list-related functionality
def list_handler(sock, packet, client_address):
    try:
        if packet.type == 'INIT_LIST':
            init_list(sock, packet.data, client_address)
        elif packet.type == 'LIST_AUTHENTICATION':
            authenticate_list(sock, packet.data, client_address)
    except ValueError, error:
        packet = Packet('ERROR', {'message': str(error)})
        sock.sendto(pickle.dumps(packet), client_address)
        if client_address in user_list_status_dict:
            del user_list_status_dict[client_address]
    except:
        packet = Packet('ERROR', {'message': 'Failed to list. Please try again.'})
        sock.sendto(pickle.dumps(packet), client_address)
        if client_address in user_list_status_dict:
            del user_list_status_dict[client_address]


# Receives the initial logout message from client; performs verification using challenge-response
def init_logout(sock, packet, client_address, server_private):
    decrypted_message = Logout.verify_logout_message(packet.data, server_private)
    if str(user_login_info_dict[client_address].cookie) != str(decrypted_message['dos_cookie']):
        error_packet = Packet("ERROR", {"message": "There has been an attack. Invalid DOS cookie received."})
        sock.sendto(pickle.dumps(error_packet), client_address)
    else:
        user_logout_nonces[client_address] = str(random.getrandbits(8 * NONCE_SIZE))
        iv, cipher_text, tag = Logout.server_sends_nonce(decrypted_message['nonce'],
                                                        user_logout_nonces[client_address],
                                                        user_login_info_dict[client_address].session_key)
        packet = Packet("LOGOUT_RESPONSE", {"cipher_text": cipher_text, "iv": iv, "tag": tag})
        sock.sendto(pickle.dumps(packet), client_address)


# Logs out the client from the dictionary; notifies all clients of this activity
def logout(sock, client_address):
    # Loop though user_list_status,user_login_info_dict,user_address_dict,user_logout_nonces:
    # if user exists delete all entries with this user
    user = user_login_info_dict[client_address].username
    # Goes over the dictionary to -  notify involved clients; deletes corresponding record
    for key, value in online_users_dict.items():
        position = -1
        if client_address == key[0]:
            position = 1
        elif client_address == key[1]:
            position = 0
        if position != -1:
            iv, cipher_text, tag = Logout.encrypt_logout_broadcast(user, user_login_info_dict[key[position]].session_key)
            packet = Packet("PERFORM_LOGOUT", {"iv": iv, "cipher_text": cipher_text, "tag": tag})
            sock.sendto(pickle.dumps(packet), key[position])
            del online_users_dict[key]

    # Performs logout for the requested client
    iv, cipher_text, tag = Logout.encrypt_logout_broadcast(user, user_login_info_dict[client_address].session_key)
    packet = Packet("LOGGING_OUT", {"iv": iv, "cipher_text": cipher_text, "tag": tag})
    sock.sendto(pickle.dumps(packet), client_address)

    # Remove all occurrences of client involvement in various dictionaries
    if client_address in user_login_info_dict:
        del user_login_info_dict[client_address]
    if user in user_address_dict:
        del user_address_dict[user]
    if client_address in user_list_status_dict:
        del user_list_status_dict[client_address]
    if client_address in user_logout_nonces:
        del user_logout_nonces[client_address]


# Once response is received from client, performs logout
def confirm_logout(sock, packet, client_address):
    expected_nonce = int(user_logout_nonces[client_address]) - 1
    if Logout.server_verifies_nonce3(packet.data['cipher_text'], packet.data['iv'], packet.data['tag'],
                                     user_login_info_dict[client_address].session_key, expected_nonce):
        logout(sock, client_address)
    else:
        error_packet = Packet("ERROR", {"message": "Problem occurred while logging out."})
        sock.sendto(pickle.dumps(error_packet), client_address)


# Handles logout-related functionality
def logout_handler(sock, packet, client_address, server_private):
    if packet.type == 'INIT_LOGOUT':
        init_logout(sock, packet, client_address, server_private)
    elif packet.type == 'VERIFY_LOGOUT':
        confirm_logout(sock, packet, client_address)


# Handles ticket creation and issuing responsibilities
def ticket_handler(sock, packet, client_address):
    if client_address not in user_login_info_dict or not type(user_login_info_dict[client_address]) is LoggedUser:
        error_packet = Packet("ERROR", {"message": "Authenticity cannot be ensured."})
        sock.sendto(pickle.dumps(error_packet), client_address)
    # Decrypt to get the sender receiver
    else:
        sender = user_login_info_dict[client_address]
        encrypted_receiver = NeedhamSchroeder.get_decrypted_message(packet.data['sender_receiver_encrypted'],
                                                                   packet.data['iv'],
                                                                   packet.data['tag'],
                                                                   sender.session_key)
        receiver_pickle = pickle.loads(encrypted_receiver)
        receiver = receiver_pickle['receiver']
        if receiver not in user_address_dict:
            error_packet = Packet("ERROR", {"message": "Receiver not connected at this moment!"})
            sock.sendto(pickle.dumps(error_packet), client_address)
        else:
            # Get receiver info once he is validated
            receiver_address = user_address_dict[receiver]
            encrypted_from_receiver = packet.data['encrypted_from_receiver']
            output = AES.decrypt(encrypted_from_receiver['cipher_text'],
                                 user_login_info_dict[receiver_address].session_key,
                                 encrypted_from_receiver['iv'], encrypted_from_receiver['tag'])
            output = pickle.loads(output)
            if output['sender'] != sender.username:
                error_packet = Packet("ERROR", {"message": "Incorrect Sender"})
                sock.sendto(pickle.dumps(error_packet), client_address)
            else:
                # Ticket containing receiver info sent to sender
                sender_receiver_key = os.urandom(32)
                # Creates ticket
                iv, ticket, tag = NeedhamSchroeder.ticket_creator(sender.username, receiver,
                                                                  output['nonce'],
                                                                  sender_receiver_key,
                                                                  user_login_info_dict[
                                                                                 receiver_address].session_key)
                ticket = {"iv": iv, "ticket": ticket, "tag": tag}
                # Issues ticket
                iv, cipher_text, tag = NeedhamSchroeder.ticket_issuer(packet.data['nonce'], receiver,
                                                                     sender_receiver_key, ticket,
                                                                     user_login_info_dict[
                                                                               client_address].session_key)
                packet = Packet("TICKET", {"iv": iv, "cipher_text": cipher_text, "tag": tag})
                sock.sendto(pickle.dumps(packet), client_address)
                online_users_dict[(client_address, receiver_address)] = sender_receiver_key


# Verifies the Needham-Schoeder init request message received from the client; sends response
def ns_initiator(sock, packet, client_address, server_private):
    if client_address not in user_login_info_dict or not type(user_login_info_dict[client_address]) is LoggedUser:
        error_packet = Packet("ERROR", {"message": "Sender not verified"})
        sock.sendto(pickle.dumps(error_packet), client_address)
    else:
        # Verifies init request from client
        receiver, sender = NeedhamSchroeder.verify_init_message(packet.data, server_private,
                                                                user_login_info_dict[
                                                                   client_address].session_key,
                                                                user_login_info_dict[client_address].cookie)
        if receiver not in user_address_dict:
            error_packet = Packet("ERROR", {"message": "Receiver not connected at this moment!"})
            sock.sendto(pickle.dumps(error_packet), client_address)
        else:
            # Sends reply to client
            receiver_address = user_address_dict[receiver]
            # Send server_reply_to_init here
            iv, cipher_text, tag = NeedhamSchroeder.server_reply_to_init(receiver_address,
                                                                        receiver, sender,
                                                                        user_login_info_dict[
                                                                         receiver_address].session_key,
                                                                        user_login_info_dict[
                                                                         client_address].session_key)
            packet = Packet("SERVER_INIT_RESPONSE", {"iv": iv, "cipher_text": cipher_text, "tag": tag})
            sock.sendto(pickle.dumps(packet), client_address)


# receive packets for login, list, send message commands in UDP.
def receive_msg(sock, stored_passwords, g, p, server_private):
    while True:
        try:
            packet, client_address = sock.recvfrom(BUFFER_SIZE)
            packet = pickle.loads(packet)
            # Handles Login
            if packet.type == 'LOGIN' or packet.type == 'INITIATE_LOGIN' \
                    or packet.type == 'AUTHENTICATION':
                login_handler(packet, sock, stored_passwords, client_address, g, p)
            # Handles List
            elif packet.type == 'INIT_LIST' or packet.type == 'LIST_AUTHENTICATION':
                list_handler(sock, packet, client_address)
            # Handles Needham-Schroeder initial messages
            elif packet.type == "INIT":
                ns_initiator(sock, packet, client_address, server_private)
            # Server acts as a KDC
            elif packet.type == "FETCHING_TICKET":
                ticket_handler(sock, packet, client_address)
            # Handles Logout
            elif packet.type == "INIT_LOGOUT" or packet.type == "VERIFY_LOGOUT":
                logout_handler(sock, packet, client_address, server_private)
            else:
                raise ValueError('Something went wrong.')
        except ValueError as error:
            print 'Error while login: %s' % error
        except:
            print 'Failure while performing operations'


# loading all the stored passwords
def load_passwords(passwords_file):
    # read entered stored credentials from the file
    stored_passwords = {}
    with open(passwords_file) as f:
        for line in f:
            words = line.split(' ')
            # Creates a dictionary[username : password]; where password
            # is g^x ; with x as Hash(Password)
            stored_passwords[words[0]] = words[1]
    return stored_passwords


# INITIALIZING SERVER
def init_server():
    config = ConfigParser.RawConfigParser()
    config.read(sever_cfg_filename)
    passwords_file = config.get('passwords', 'filename')
    g = config.getint('DH_config', 'g')
    p = long(config.get('DH_config', 'p'), 16)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((config.get('my_address', 'ip_address'), config.getint('my_address', 'port')))
    global private_key_file
    global public_key_file
    private_key_file = config.get('server_keys', 'private_key')
    public_key_file = config.get('server_keys', 'public_key')
    stored_passwords = load_passwords(passwords_file)
    return g, p, stored_passwords, server_socket


def main():
    print "The usage of this program is as follows:"
    print "Type START to kick start the server; STOP to terminate the server!!!!!"
    while True:
        try:
            command = raw_input()
            if command == "START":
                (g, p, stored_passwords, server_socket) = init_server()
                Thread(target=receive_msg, args=(server_socket, stored_passwords, g, p, private_key_file)).start()
                print 'Server is running at: ' + socket.gethostbyname(socket.gethostname()) + ' ' + str(
                    server_socket.getsockname()[1])
            elif command == "STOP":
                print "The server has been terminated!"
                os._exit(0)
            else:
                print "Please enter either START or STOP"
        except KeyboardInterrupt:
            try:
                sys.exit(0)
            except SystemExit:
                os._exit(0)
        except Exception, e:
            print 'Error found: %s' % e


if __name__ == "__main__":
    main()
