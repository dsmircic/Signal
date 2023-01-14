# #!/usr/bin/env python3

import pickle
import os

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

from base64 import b64encode

from Crypto import Crypto

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
        # Inicijalni Diffie-Hellman par ključeva iz metode `generate_certificate`
        self.current_key_pair = tuple()

        self.ck_send_user = dict()
        self.ck_rec_user = dict()
        self.root_chain = dict()

        self.private_key = parameters.generate_private_key()
        self.public_key = self.private_key.public_key()

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
        self.current_key_pair = parameters.generate_private_key()

        # Serialize public key


        # Return certificate
        data = {'name': self.username,
                'public_key': self.get_bytes_from_key(self.current_key_pair.public_key())
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
        self.conns[cert['name']] = public_key

        # exchange keys
        self.root_chain[cert['name']] = self.current_key_pair.exchange(public_key)
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
        if self.ck_send_user.get(username) is None:
            self.ck_send_user[username] = self.root_chain[username]
        
        root_key = self.ck_send_user[username]
        new_rk, mk = Crypto.KDF(rootKey=root_key)

        self.root_chain[username] = new_rk

        # encrypt message
        ciphertext, iv = Crypto.encrypt(mk, message)

        # create header
        header = {
            'iv' : iv,
            'public_key' : self.get_bytes_from_key(self.current_key_pair.public_key())
        }

        # create message
        data = {
            'header' : header,
            'ciphertext' : ciphertext,
            'sender' : self.username
        }

        # update sending chain
        self.ck_send_user[username] = new_rk

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
        header = message['header']
        iv = header['iv']
        ciphertext = message['ciphertext']

        peer_public_key = serialization.load_pem_public_key(header['public_key'], backend=default_backend())

        if self.ck_rec_user.get(username) is None:
            self.ck_rec_user[username] = self.root_chain[username]

        root_key = self.ck_rec_user[username]
        new_rk, mk = Crypto.KDF(rootKey=root_key)

        self.root_chain[username] = new_rk

        # decrypt message
        plaintext = Crypto.decrypt(messageKey=mk, ciphertext=ciphertext, iv=iv)

        if peer_public_key != self.conns[username]:
            self.current_key_pair = parameters.generate_private_key()

        # update receiving chain
        self.ck_rec_user[username] = new_rk
        return plaintext


def main():
    pass


if __name__ == "__main__":
    main()
