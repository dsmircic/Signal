#!/usr/bin/env python3

import pickle
import os

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

from base64 import b64decode, b64encode

from Crypto import Crypto


class MessengerClient:
    """ Messenger client klasa

        Slobodno mijenjajte postojeće atribute i dodajte nove kako smatrate
        prikladnim.
    """

    def __init__(self, username, ca_pub_key):
        """ Inicijalizacija klijenta

        Argumenti:
        username (str) -- ime klijenta
        ca_pub_key     -- javni ključ od CA (certificate authority)

        """
        self.username = username
        self.ca_pub_key = ca_pub_key
        # Aktivne konekcije s drugim klijentima
        self.conns = {}
        # Inicijalni Diffie-Hellman par ključeva iz metode `generate_certificate`
        self.dh_key_pair = dict()
        self.key_chain_init()

    def key_chain_init(self):
        self.ck_send_user = dict()
        self.ck_rec_user = dict()

    def add_connection(self, username, ck_send, ck_rec):
        self.ck_send_user[username] = ck_send
        self.ck_rec_user[username] = ck_rec

    def generate_certificate(self):
        """ Generira par Diffie-Hellman ključeva i vraća certifikacijski objekt

        Metoda generira inicijalni Diffie-Hellman par kljuceva; serijalizirani
        javni kljuc se zajedno s imenom klijenta postavlja u certifikacijski
        objekt kojeg metoda vraća. Certifikacijski objekt moze biti proizvoljan (npr.
        dict ili tuple). Za serijalizaciju kljuca mozete koristiti
        metodu `public_bytes`; format (PEM ili DER) je proizvoljan.

        Certifikacijski objekt koji metoda vrati bit će potpisan od strane CA te
        će tako dobiveni certifikat biti proslijeđen drugim klijentima.

        """

        # Generate Diffie-Hellman key pair
        key_pair = dh.generate_parameters(
            generator=2, key_size=2048, backend=default_backend()).generate_private_key()
        # Serialize public key
        public_key = key_pair.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        self.dh_key_pair[self.username] = public_key

        # Return certificate
        data = {'name': self.username,
                'public_key': public_key
                }
        return data

    def receive_certificate(self, cert, signature):
        """ Verificira certifikat klijenta i sprema informacije o klijentu (ime
            i javni ključ)

        Argumenti:
        cert      -- certifikacijski objekt
        signature -- digitalni potpis od `cert`

        Metoda prima certifikacijski objekt (koji sadrži inicijalni
        Diffie-Hellman javni ključ i ime klijenta) i njegov potpis kojeg
        verificira koristeći javni ključ od CA i, ako je verifikacija uspješna,
        sprema informacije o klijentu (ime i javni ključ). Javni ključ od CA je
        spremljen prilikom inicijalizacije objekta.

        """
        # Deserialize the public key from the certificate
        public_key = serialization.load_pem_public_key(
            cert['public_key'],
            backend=default_backend()
        )

        # Verify the signature using the CA's public key
        try:
            self.ca_pub_key.verify(
                signature,
                pickle.dumps(cert),
                ec.ECDSA(hashes.SHA256())
            )
        except InvalidSignature:
            # Signature is invalid, do not trust the certificate
            print("Invalid signature")
            return False

        # Signature is valid, store the client's name and public key
        self.conns[cert['name']] = public_key
        print(self.conns)
        return True


    def send_message(self, username, message):
        """ Slanje poruke klijentu

        Argumenti:
        message  -- poruka koju ćemo poslati
        username -- klijent kojem šaljemo poruku `message`

        Metoda šalje kriptiranu poruku sa zaglavljem klijentu s imenom `username`.
        Pretpostavite da već posjedujete certifikacijski objekt od klijenta
        (dobiven pomoću `receive_certificate`) i da klijent posjeduje vaš.
        Ako već prije niste komunicirali, uspostavite sesiju tako da generirate
        nužne `double ratchet` ključeve prema specifikaciji.

        Svaki put kada šaljete poruku napravite `ratchet` korak u `sending`
        lanacu (i `root` lanacu ako je potrebno prema specifikaciji).  S novim
        `sending` ključem kriptirajte poruku koristeći simetrični kriptosustav
        AES-GCM tako da zaglavlje poruke bude autentificirano.  Ovo znači da u
        zaglavlju poruke trebate proslijediti odgovarajući inicijalizacijski
        vektor.  Zaglavlje treba sadržavati podatke potrebne klijentu da
        derivira novi ključ i dekriptira poruku.  Svaka poruka mora biti
        kriptirana novim `sending` ključem.

        Metoda treba vratiti kriptiranu poruku zajedno sa zaglavljem.

        """
        if username not in self.ck_send_user.keys():
            self.ck_send_user[username] = self.conns[username]

        ck_send = self.ck_send_user[username].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        new_ck, new_mk = Crypto.KDF(ck_send)

        ciphertext, iv = Crypto.encrypt(
            messageKey=new_mk, plaintext=message)

        self.ck_send_user[username] = new_ck

        header = dict()
        header["public_key"] = ck_send
        header["iv"] = iv

        data = dict()
        data["ciphertext"] = ciphertext
        data["sender"] = self.username

        print(self.username + " ciphertext: " + ciphertext)
 
        return (header, data)

    def check_user(self, username):
        if username not in self.ck_rec_user.keys():
            self.ck_rec_user[username] = self.conns[username]
    
    def receive_message(self, username, message):
        """ Primanje poruke od korisnika

        Argumenti:
        message  -- poruka koju smo primili
        username -- klijent koji je poslao poruku

        Metoda prima kriptiranu poruku od klijenta s imenom `username`.
        Pretpostavite da već posjedujete certifikacijski objekt od klijenta
        (dobiven pomoću `receive_certificate`) i da je klijent izračunao
        inicijalni `root` ključ uz pomoć javnog Diffie-Hellman ključa iz vašeg
        certifikata.  Ako već prije niste komunicirali, uspostavite sesiju tako
        da generirate nužne `double ratchet` ključeve prema specifikaciji.

        Svaki put kada primite poruku napravite `ratchet` korak u `receiving`
        lanacu (i `root` lanacu ako je potrebno prema specifikaciji) koristeći
        informacije dostupne u zaglavlju i dekriptirajte poruku uz pomoć novog
        `receiving` ključa. Ako detektirate da je integritet poruke narušen,
        zaustavite izvršavanje programa i generirajte iznimku.

        Metoda treba vratiti dekriptiranu poruku.

        """

        self.check_user(username)

        data = message[1]
        header = message[0]

        pub_key = header["public_key"]

        text = b64decode(data["ciphertext"])
        iv = bytes(b64decode(header["iv"]))

        new_ck, new_mk = Crypto.KDF(pub_key)
        plaintext = Crypto.decrypt(messageKey=new_mk, ciphertext=text, iv=iv)

        self.ck_rec_user[username] = new_ck

        print(self.username + "plaintext: " + plaintext.decode())

        return plaintext.decode()


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


def generate_p384_key_pair():
    secret_key = ec.generate_private_key(ec.SECP384R1())
    public_key = secret_key.public_key()
    return (secret_key, public_key)


def sign_with_ecdsa(secret_key, data):
    signature = secret_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return signature


def main():
    ca_sk, ca_pk = generate_p384_key_pair()

    alice = MessengerClient('Alice', ca_pk)
    bob = MessengerClient('Bob', ca_pk)

    alice_cert = alice.generate_certificate()
    bob_cert = bob.generate_certificate()

    alice_cert_sign = sign_with_ecdsa(ca_sk, pickle.dumps(alice_cert))
    bob_cert_sign = sign_with_ecdsa(ca_sk, pickle.dumps(bob_cert))

    alice.receive_certificate(bob_cert, bob_cert_sign)
    bob.receive_certificate(alice_cert, alice_cert_sign)

    plaintext = 'Hi Bob!'
    message = alice.send_message('Bob', plaintext)

    received_message = bob.receive_message('Alice', message=message)

    input("Press enter to continue...")
    pass


if __name__ == "__main__":
    main()
