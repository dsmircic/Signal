# #!/usr/bin/env python3

import pickle
import os

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


from Crypto import Crypto
from State import State

parameters = dh.generate_parameters(generator=2, key_size=512)


class MessengerClient:
    """ Messenger client klasa

        Slobodno mijenjajte postojeće atribute i dodajte nove kako smatrate
        prikladnim.
    """

    def __init__(self, username, ca_public_key):
        """ Inicijalizacija klijenta

        Argumenti:
        username (str) -- ime klijenta
        ca_public_key     -- javni ključ od CA (certificate authority)

        """
        self.username = username
        self.ca_public_key = ca_public_key
        # Aktivne konekcije s drugim klijentima
        self.conns = {}
        self.last_message = dict()


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
        self.initial_key_pair = parameters.generate_private_key()

        # Return certificate
        data = {'name': self.username,
                'public_key': self.get_bytes_from_key(self.initial_key_pair.public_key())
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
            self.ca_public_key.verify(
                signature,
                pickle.dumps(cert),
                ec.ECDSA(hashes.SHA256())
            )
        except InvalidSignature:
            # Signature is invalid, do not trust the certificate
            print("Invalid signature")
            return False

        # Signature is valid, store the client's name and public key
        self.conns[cert['name']] = State(
            self.initial_key_pair, public_key, None, None)
        return True

    def get_bytes_from_key(self, key):
        return key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

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
        if self.conns[username].reset:

            dh_private_key = parameters.generate_private_key()

            peer_public_key = self.conns[username].peer_public_key
            shared_key = dh_private_key.exchange(peer_public_key)

            new_rk, mk = Crypto.KDF(rootKey=shared_key)
            self.conns[username] = State(
                dh_private_key, peer_public_key, new_rk, mk)

        new_rk, mk = Crypto.KDF(rootKey=self.conns[username].root_key)
        self.conns[username].root_key = new_rk
        self.conns[username].sending_key = mk

        ciphertext, iv = Crypto.encrypt(
            self.conns[username].sending_key, message)
        public_key_serialized = self.get_bytes_from_key(
            self.conns[username].key_pair.public_key())

        header = {
            'iv': iv,
            'public_key': public_key_serialized
        }

        data = {
            'ciphertext': ciphertext,
            'iv': iv,
            'header': header
        }

        return data

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

        if self.last_message.get(username) is None:
            self.last_message[username] = message['ciphertext']
        else:
            if self.last_message[username] == message['ciphertext']:
                raise Exception("Replay attack detected!")
            else:
                self.last_message[username] = message['ciphertext']

        old_peer_public_key = self.get_bytes_from_key(
            self.conns[username].peer_public_key)
        new_peer_public_key = message['header']['public_key']

        if new_peer_public_key != old_peer_public_key:

            dh_private_key = self.conns[username].key_pair
            peer_public_key = serialization.load_pem_public_key(
                new_peer_public_key)

            shared_key = dh_private_key.exchange(peer_public_key)

            root_key, mk = Crypto.KDF(rootKey=shared_key)
            self.conns[username] = State(
                dh_private_key, peer_public_key, root_key, mk)
        else:
            self.conns[username].reset = False

        self.conns[username].reset = True
        _, mk = Crypto.KDF(rootKey=self.conns[username].root_key)

        return Crypto.decrypt(mk, message['ciphertext'], message['iv'])

# def generate_p384_key_pair():
#     secret_key = ec.generate_private_key(ec.SECP384R1())
#     public_key = secret_key.public_key()
#     return (secret_key, public_key)

# def sign_with_ecdsa(secret_key, data):
#     signature = secret_key.sign(data, ec.ECDSA(hashes.SHA256()))
#     return signature


def main():
    # ca_sk, ca_pk = generate_p384_key_pair()

    # alice = MessengerClient('Alice', ca_pk)
    # bob = MessengerClient('Bob', ca_pk)

    # alice_cert = alice.generate_certificate()
    # bob_cert = bob.generate_certificate()

    # alice_cert_sign = sign_with_ecdsa(ca_sk, pickle.dumps(alice_cert))
    # bob_cert_sign = sign_with_ecdsa(ca_sk, pickle.dumps(bob_cert))

    # alice.receive_certificate(bob_cert, bob_cert_sign)
    # bob.receive_certificate(alice_cert, alice_cert_sign)

    # plaintext = 'Hi Bob!'
    # message = alice.send_message('Bob', plaintext)

    # result = bob.receive_message('Alice', message)
    # print(plaintext, result)

    # plaintext = 'Hey Alice!'
    # message = bob.send_message('Alice', plaintext)

    # result = alice.receive_message('Bob', message)
    # print(plaintext, result)

    # plaintext = 'Are you studying for the exam tomorrow?'
    # message = bob.send_message('Alice', plaintext)

    # result = alice.receive_message('Bob', message)
    # print(plaintext, result)

    # plaintext = 'Yes. How about you?'
    # message = alice.send_message('Bob', plaintext)

    # result = bob.receive_message('Alice', message)
    # print(plaintext, result)
    pass


if __name__ == "__main__":
    main()
