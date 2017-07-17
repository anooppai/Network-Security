import argparse
import sys
import socket
import pickle
from packet import Packet

#Maximum UDP Packet size
buffer_size = 65507
#Dictionary of Users signed in with their IPs
users = {}

#Subroutine responsible for starting communication
def dispatch_messages(my_socket):
    while 1:
        try:
            #get data from socket
            content, client_address = my_socket.recvfrom(buffer_size)
        except socket.error as ex:
            print "Socket exception occured : %s " % ex
            continue
        try:
            #Use pickle to convert string  an object hierarchy
            udp_packet = pickle.loads(content)
        except pickle.UnpicklingError as ex:
            print "Pickling error occured : %s " %ex
            continue
        #Check for different types of packet
        if udp_packet.type  == 'SIGN-IN':
            #Creates a username -> IP mapping
            users[udp_packet.data.get('username')] = client_address
        elif udp_packet.type == 'LIST':
            #Display dictionary keys
            user_list = list(users.keys())
            user_list = ", ".join(user_list)
            user_list = "Signed In Users: " + user_list
            list_packet = Packet('LIST', {'data' : user_list})
            try:
                #Send to client address after converting object to string
                my_socket.sendto(pickle.dumps(list_packet), client_address)
            except socket.error as ex:
                print "Socket exception occured : %s " % ex
                continue
            except pickle.UnpicklingError as ex:
                print "Pickling error occured : %s " % ex
                continue
        elif udp_packet.type == 'MESSAGE':
            #Returns the destination client's ip and port number
            dest = users.get(udp_packet.data.get('dest-name'))
            #Check if no tuple was returned
            if dest is None:
                print "Entered username is not signed in yet"
                continue
            created_packet = Packet('RECEIVING',
                                    {'dest': dest,
                                     'origin-ip' : client_address[0],
                                    'origin-port' : client_address[1]})
            try:
                # Send to client address after converting object to string
                my_socket.sendto(pickle.dumps(created_packet), client_address)
            except socket.error as ex:
                print "Socket exception occured : %s " % ex
                continue
            except pickle.UnpicklingError as ex:
                print "Pickling error occured : %s " % ex
                continue

def main():
    #Read input from command line prompt
    parser = argparse.ArgumentParser()
    parser.add_argument('-sp', '--port', help = "Server runs on this port")

    args = parser.parse_args()
    port = args.port

    #Check if no port was specified
    if port is None:
        print 'No port was specified. Invalid Usage : Command should be server.py -sp <port>'
        return

    try:
        #Creates a socket for UDP server communication
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_address = ('localhost', int(port))
        #Bind socket to server ip and port
        my_socket.bind(server_address)
        print "Server Initialized..."
    except socket.error as ex:
        print "Socket exception occured: %s" %ex
        return

    #Function call that begins all forms of communication with the client
    dispatch_messages(my_socket)

if __name__ == "__main__":
    main()

