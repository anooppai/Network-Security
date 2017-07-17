import pickle
import AES
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class MessageExchangeProtocol(object):
    # username: client A
    # other_username: client B involved in the communication
    # seq_no: A's sequence number
    # remote_seq_no: B's sequence number
    # increment: Increment value for A
    # other_increment: Increment value for B
    # key: g^(a*b) mod p + nonceA + nonceB
    def __init__(self, username, remote_username, seq_no, remote_seq_no, increment,
                 remote_increment, key):
        self.username = username
        self.remote_username = remote_username
        self.seq_no = seq_no
        self.remote_seq_no = remote_seq_no
        self.increment = increment
        self.remote_increment = remote_increment
        self.shared_key = str(key)

    # Sends hash of key that is shared and its sequence number
    def send_key(self):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(self.shared_key + str(self.seq_no))
        return digest.finalize()

    # Sends hash of key that is shared and other client's sequence number
    def receive_key(self):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(self.shared_key + str(self.remote_seq_no))
        return digest.finalize()

    # Encrypts the message before sending; increments sequence number
    # by the specified value
    def send_message(self, message):
        packet = (self.username, message)
        iv, cipher_text, tag = AES.encrypt(pickle.dumps(packet), self.send_key())
        self.seq_no += self.increment
        return iv, cipher_text, tag

    # Decrypts the received message; increments sequence number received
    # by the specified value
    def receive_message(self, cipher_text, iv, tag):
        message = AES.decrypt(cipher_text, self.receive_key(), iv, tag)
        self.remote_seq_no += self.remote_increment
        username, message = pickle.loads(message)
        # Throw an error in the event when the username received is not as desired
        if self.remote_username != username:
            raise ValueError('Incorrect username')
        return self.remote_username + '> ' + message
