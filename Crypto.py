from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from base64 import b64decode, b64encode

from cryptography.hazmat.primitives import hashes

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

        return ciphertext, iv

    @staticmethod
    def decrypt(messageKey, ciphertext, iv: bytes):
        cipher = AES.new(
            nonce=iv,
            key=messageKey,
            mode=AES.MODE_GCM
        )

        return cipher.decrypt(ciphertext).decode('utf-8')

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
