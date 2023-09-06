# #!/usr/bin/env python3

from genericpath import getsize
import json
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64decode, b64encode


class MessengerClient:
    """ Messenger client class

        Feel free to modify the attributes and add new ones as you
        see fit.

    """

    def __init__(self, username, max_skip=10):
        """ Initializes a client

        Arguments:
        username (str) -- client name
        max_skip (int) -- Maximum number of message keys that can be skipped in
                          a single chain

        """
        self.username = username
        # Maximum number of message keys that can be skipped in a single chain
        self.max_skip = max_skip
        self.keyChainInit()

        MessengerClient.emptyMessages(self.username)

    @staticmethod
    def emptyMessages(username):
        FileManipulator.empty_messages(f"comms/{username}.json")

    def keyChainInit(self):
        self.chainKeySendUser = dict()
        self.chainKeyRecUser = dict()
        self.lostMessageKeys = dict()

        self.messagesReceived = dict()
        self.messagesSent = dict()

    def add_connection(self, username, chain_key_send, chain_key_recv):
        """ Add a new connection

        Arguments:
        username (str) -- user that we want to talk to
        chain_key_send -- sending chain key (CKs) of the username
        chain_key_recv -- receiving chain key (CKr) of the username

        """
        self.chainKeySendUser[username] = chain_key_send
        self.chainKeyRecUser[username] = chain_key_recv

        self.messagesSent[username] = 0

    def send_message(self, username, message):
        """ Send a message to a user

        Get the current sending key of the username, perform a symmetric-ratchet
        step, encrypt the message, update the sending key, return a header and
        a ciphertext.

        Arguments:
        username (str) -- user we want to send a message to
        message (str)  -- plaintext we want to send

        Returns a ciphertext and a header data (you can use a tuple object)

        """
        chainKeySend = self.chainKeySendUser[username]
        newChainKey, ciphertext, iv = Crypto.ratchetEncrypt(
            plaintext=message, chainKey=chainKeySend)

        self.chainKeySendUser[username] = newChainKey

        header = {
            "id": self.messagesSent[username]
        }

        dictionary = {
            "sender": self.username,
            "ciphertext": ciphertext,
            "iv": iv,
            "header": header
        }

        self.messagesSent[username] += 1

        with open(f"comms/{username}.json", "r+") as fp:
            if getsize(f"comms/{username}.json") != 0:
                listObj = json.load(fp)
            else:
                listObj = list()

        listObj.append(dictionary)
        FileManipulator.write_to_JSON(f"comms/{username}.json", listObj)

        return (dictionary["ciphertext"], dictionary["header"])

    def checkIsKnownUser(self, username):
        if username not in self.chainKeyRecUser.keys():
            raise Exception("Unknown user")

    def receive_message(self, username: str, message) -> str:
        """ Receive a message from a user

        Get the username connection data, check if the message is out-of-order,
        perform necessary symmetric-ratchet steps, decrypt the message and
        return the plaintext.

        Arguments:
        username (str) -- user who sent the message
        message        -- a ciphertext and header data

        Returns a plaintext (str)

        """
        self.checkIsKnownUser(username=username)

        text = message[0]
        header = message[1]
        messageID = header["id"]

        if username not in self.messagesReceived.keys():
            self.messagesReceived[username] = 0
        else:
            self.messagesReceived[username] += 1

        self.trySkippedMessages(messageID=messageID, username=username)

        data = FileManipulator.read_from_JSON(f"comms/{self.username}.json")

        lostMessageKey = self.checkLostMessages(
            username=username, id=messageID)

        firstIndex = self.findMessageIndex(
            username=username, messages=data, id=messageID)

        if firstIndex != -1:
            text = b64decode(data[firstIndex]["ciphertext"])
            iv = bytes(b64decode(data[firstIndex]["iv"]))
            data.remove(data[firstIndex])

        FileManipulator.write_to_JSON(f"comms/{self.username}.json", data=data)

        if lostMessageKey != None:
            plaintext = Crypto.decrypt(lostMessageKey, text, iv)
        else:
            newChainKey, plaintext = Crypto.ratchetDecrypt(
                ciphertext=text,
                chainKey=self.chainKeyRecUser[username],
                iv=iv)

            self.chainKeyRecUser[username] = newChainKey

        return plaintext.decode()

    def findMessageIndex(self, username, messages, id: int) -> int:
        """Find first occurance of message with the given id

        Arguments:
            username: user who sent the message
            messages: received messages
            id:       message id

        Return:
            index of the message withing the .json file
        """
        index = 0
        for i in messages:
            if i["sender"] == username and i["header"]["id"] == id:
                return index

            index += 1

        return -1

    def storeLostMessageKeys(self, start, numberOfLostKeys: int, username):
        """Stores message keys from messages which were skipped

        Generate numberOfLostKeys messageKeys and store them in a dictionary.

        lostMessageKeys:
            key -> sender name
            value -> list of dictionaries:
                key -> lost message ID
                value -> messageKey

        Arguments:
            start: last known message id
            numberOfLostKeys: number of messages which were lost
            username: user who sent the message
        """
        currentRootKey = self.chainKeyRecUser[username]

        for i in range(0, numberOfLostKeys):
            currentRootKey, messageKey = Crypto.KDF(currentRootKey)

            if username not in self.lostMessageKeys.keys():
                self.lostMessageKeys[username] = list()

            self.lostMessageKeys[username].append({start + i: messageKey})

        self.chainKeyRecUser[username] = currentRootKey

    def checkLostMessages(self, username, id):
        """Checks if the received message was skipped, and returns it's message key if it was

        Arguments:
            username: user who sent the message
            id: potential lost message id

        Returns:
            messageKey if the message was actually lost,
            None if the message wasn't lost
        """
        if username in self.lostMessageKeys.keys():
            lostMessageKeyIDs = self.lostMessageKeys[username]
        else:
            return None

        for i in lostMessageKeyIDs:
            if id in i.keys():
                key = i[id]
                del i
                return key

        return None

    def trySkippedMessages(self, messageID: int, username):
        """Check if there are skipped messages from a user

            IF there are skipped messages, store their message keys for later decryption
        """
        messagesMissed = messageID - self.messagesReceived[username]

        if messagesMissed > 0 and messagesMissed <= self.max_skip:
            self.storeLostMessageKeys(
                numberOfLostKeys=messagesMissed, username=username, start=self.messagesReceived[username])


class Crypto:
    @staticmethod
    def KDF(rootKey):
        """Generates a new chain key and a message key

        HKDF hashing algorithm which produces a hash of the root key salted with the:
            CK_constant --> new chain key
            SK_constant --> new message key
        """
        CK_constant = b"top_secret_encryption_key_uncrackable"
        MK_constant = b"uncrackable_key_encryption_secret_top"

        newChainKey_HKDF = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=CK_constant,
            info=None
        )

        newChainKey = newChainKey_HKDF.derive(bytes(rootKey))

        messageKey_HKDF = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=MK_constant,
            info=None
        )

        messageKey = messageKey_HKDF.derive(bytes(rootKey))
        return newChainKey, messageKey

    @staticmethod
    def encrypt(messageKey, plaintext):
        iv = get_random_bytes(16)
        cipher = AES.new(
            nonce=iv,
            key=messageKey,
            mode=AES.MODE_GCM
        )
        ciphertext = cipher.encrypt(bytes(plaintext, 'utf-8'))

        return b64encode(ciphertext).decode(), b64encode(iv).decode()

    @staticmethod
    def decrypt(messageKey, ciphertext, iv: bytes):
        cipher = AES.new(
            nonce=iv,
            key=messageKey,
            mode=AES.MODE_GCM
        )

        return cipher.decrypt(ciphertext)

    @staticmethod
    def ratchetEncrypt(plaintext, chainKey):
        newChainKey, messageKey = Crypto.KDF(chainKey)
        ciphertext, iv = Crypto.encrypt(
            messageKey=messageKey, plaintext=plaintext)

        return newChainKey, ciphertext, iv

    @staticmethod
    def ratchetDecrypt(ciphertext, chainKey, iv):
        newChainKey, messageKey = Crypto.KDF(chainKey)

        return newChainKey, Crypto.decrypt(messageKey=messageKey, ciphertext=ciphertext, iv=iv)


class FileManipulator:

    @staticmethod
    def write_to_JSON(path, data):
        with open(path, "w") as outfile:
            json.dump(data, outfile, indent=4, separators=(',', ': '))

    @staticmethod
    def read_from_JSON(path) -> list:
        with open(path, "r") as openfile:
            return json.load(openfile)

    @staticmethod
    def empty_messages(path):
        with open(path, "w") as outfile:
            outfile.close()
