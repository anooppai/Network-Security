import ConfigParser
from Constants import *


# function to create passwords by client
def store_user_password(g, p, username, password):
    with open(password_filename, 'a') as f:
        f.write(username + ' ' + str(convert(g, p, password)) + '\n')


def convert(g, p, password):
    binary_string = ''.join(format(ord(x), 'b') for x in password)
    number = int(binary_string, 2)
    return pow(g, number, p)


def main():
    config = ConfigParser.RawConfigParser()
    config.read(client_cfg_filename)
    g = config.getint('DH_config', 'g')
    p = long(config.get('DH_config', 'p'), 16)

    username = raw_input('Enter username: ')
    password = raw_input('Enter password: ')
    store_user_password(g, p, username, password)


if __name__ == "__main__":
    main()
