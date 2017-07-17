class Packet(object):
    def __init__(self, type, data):
        self.type = type
        self.data = data


class Cookie(object):
    def __init__(self, client_address, timestamp, puzzle):
        self.client_address = client_address
        self.timestamp = timestamp
        self.puzzle = puzzle

    def __hash__(self):
        return hash((self.client_address, self.timestamp))

    def __eq__(self, other):
        return self.client_address == other.client_address and self.timestamp == other.timestamp

    def __str__(self):
        return str(self.client_address) + ' ' + str(self.timestamp)


# user login protocol messages
class LoginInit(object):
    def __init__(self, cookie, puzzle_answer):
        self.cookie = cookie
        self.puzzle_answer = puzzle_answer


class LoginKeyExchange(object):
    def __init__(self, cookie, client_username, session_key, timestamp, expected_client_nonce):
        self.cookie = cookie
        self.client_username = client_username
        self.session_key = session_key
        self.timestamp = timestamp
        self.expected_client_nonce = expected_client_nonce


class LoggedUser(object):
    def __init__(self, cookie, client_username, session_key, timestamp):
        self.cookie = cookie
        self.username = client_username
        self.session_key = session_key
        self.timestamp = timestamp


# List Init Messages
class ListInit(object):
    def __init__(self, expected_client_nonce, timestamp):
        self.expected_client_nonce = expected_client_nonce
        self.timestamp = timestamp


# Message for key exchange between client and client
class KeyExchange(object):
    def __init__(self, username, shared_key, timestamp):
        self.shared_key = shared_key
        self.timestamp = timestamp
        self.username = username


class InitKeyExchange(object):
    def __init__(self, username, shared_key, timestamp):
        self.shared_key = shared_key
        self.timestamp = timestamp
        self.username = username


class InitMessageExchange(object):
    def __init__(self, secret, nonce, sequence_number, timestamp):
        self.secret = secret
        self.nonce = nonce
        self.sequence_number = sequence_number
        self.timestamp = timestamp