import argparse
import socket
from threading import Thread
from packet import Packet
import pickle
import sys

#Maximum UDP Packet size
buffer_size = 65507
username = ''
message = ''

#Subroutine responsible for sending messages
def dispatch_message(my_socket, server_addr):
    while 1:
        try:
            global username, message
            client_message = raw_input()
            #Checks for different type of client messages
            if client_message == 'list':
                message_packet = Packet('LIST', {})
                try:
                    # Send to server address after converting object to string
                    deliver_message = my_socket.sendto(pickle.dumps(message_packet), server_addr)
                except socket.error as ex:
                    print "Socket error encountered : %s " % ex
                    return
                except pickle.UnpicklingError as ex:
                    print "Pickling error occured : %s " % ex
                    return
                continue
            elif client_message.split()[0] == 'send':
                #Send destination ip and port as data
                message_packet = Packet('MESSAGE', {'dest-name': client_message.split()[1]})
                #Save message as a global variable
                message = client_message.split()[2:]
                message = " ".join(message)
                try:
                    #Send to server address after converting object to string
                    deliver_message = my_socket.sendto(pickle.dumps(message_packet), server_addr)
                except socket.error as ex:
                    print "Socket error encountered : %s " % ex
                    return
                except pickle.UnpicklingError as ex:
                    print "Pickling error occured : %s " % ex
                    return
                continue
        except:
            print "Username not specified! : %s " %sys.exc_info()[0]
            continue

#Subroutine responsible for receiving messages
def collect_message(my_socket):
    while 1:
        try:
            global username, message
            content, _ = my_socket.recvfrom(buffer_size)
            # Use pickle to convert string  an object hierarchy
            udp_packet = pickle.loads(content)
            #Perform actions based on type of packet
            if udp_packet.type == 'LIST':
                print udp_packet.data.get('data')
            elif udp_packet.type == 'RECEIVING':
                send_packet = Packet('MESSAGE', {'origin-ip': udp_packet.data.get('origin-ip'),
                                                 'origin-port': udp_packet.data.get('origin-port'), 'username': username ,
                                                 'data': message})
                try:
                    # Send to server address after converting object to string
                    my_socket.sendto(pickle.dumps(send_packet), udp_packet.data.get('dest'))
                except socket.error as ex:
                    print "Socket error encountered : %s " % ex
                    return
                except pickle.UnpicklingError as ex:
                    print "Pickling error occured : %s " % ex
                    return
            elif udp_packet.type == 'MESSAGE':
                # Send message to the client along with username that has to be displayed
                print '<From ' + udp_packet.data.get('origin-ip') + ':' + str(udp_packet.data.get('origin-port')) \
                      + ':' + udp_packet.data.get('username') + '>: ' + udp_packet.data.get('data')
        except socket.error as ex:
            print "Error encountered while creating sockets %s " % ex
        except pickle.UnpicklingError as ex:
            print "Pickling error occured : %s " % ex
            return



def main():
    global username
    #Read input from command line prompt
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--username', help="Client Username")
    parser.add_argument('-sip', '--server-ip', help="Server IP address")
    parser.add_argument('-sp', '--port', help="Server runs on this port")

    args = parser.parse_args()
    username = args.username
    port = args.port
    server_ip = args.server_ip

    #Check if server ip is not specified
    if server_ip is None:
        print "Invalid usage! Server IP is not specified. Follow : client.py --sip server-ip --sp port"
        return

    #Check if port is not specified
    if port is None:
        print "Invalid usage! Port number not specified. Follow : client.py --sip server-ip --sp port"
        return

    try:
        #Creates a UDP socket for Client
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        #Signs the user in
        signin_packet = Packet('SIGN-IN', {'username': username})
        #Send to server address after converting object to string
        try:
            deliver_message = my_socket.sendto(pickle.dumps(signin_packet), (server_ip, int(port)))
        except socket.error as ex:
            print "Socket error encountered : %s " % ex
            return
        except pickle.UnpicklingError as ex:
            print "Pickling error occured : %s " % ex
            return

    except socket.error as ex:
        print "Socket error encountered : %s " % ex
        return

    #Multi threading programs; send and receive simultaneously
    Thread(target=dispatch_message, args=(my_socket, (server_ip, int(port)))).start()
    Thread(target=collect_message, args=(my_socket,)).start()


if __name__ == "__main__":
    main()
