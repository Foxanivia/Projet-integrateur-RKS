import random
import socket
from keeloq import Keeloq


class Emetteur:
    def __init__(self, key: int):
        """
        Initialise une instance de la classe Emetteur avec une clé donnée.
        :param key: Clé de chiffrement utilisée pour initialiser l'instance Keeloq.
        """
        self.keeloq = Keeloq(key)
        self.counter = 0  # Compteur initial

    def send(self, data: int):
        """
        Chiffre les données données et incrémente le compteur.
        :param data: Les données à envoyer.
        :return: Les données chiffrées et le compteur utilisé.
        """
        self.counter = (self.counter + 1) & 0xF  # Incrémenter le compteur sur 4 bits pour chaque envoi
        encrypted_data = self.keeloq.encrypt(data, self.counter)
        return encrypted_data, self.counter


def main():
    # Génération d'une clé aléatoire partagée de 64 Bits
    key = random.getrandbits(64)
    print(key)
    emetteur = Emetteur(key)
    data_to_send = 0x1234567

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('localhost', 12345))
        s.listen()
        print("Emetteur en attente de connexion...")
        conn, addr = s.accept()
        with conn:
            print('Connecté par', addr)

            # Ex1: Initialisation à temps 0
            print("Initialisation :")
            encrypted_data, sent_counter = emetteur.send(data_to_send)
            conn.sendall(encrypted_data.to_bytes(8, 'big'))

            # Ex2: Resynchronisation, après une désynchronisation tolérable
            print("Désynchronisation tolérable :")
            iteration = 3
            print(f"Incrementation de l'émetteur sans reception x{iteration}")
            emetteur.counter = (emetteur.counter + iteration) & 0xF
            encrypted_data, sent_counter = emetteur.send(data_to_send)
            conn.sendall(encrypted_data.to_bytes(8, 'big'))

            # Ex3: Resynchronisation, après une désynchronisation non-tolérable
            print("Désynchronisation non-tolérable :")
            iteration = 6
            print(f"Incrementation de l'émetteur sans reception x{iteration}")
            emetteur.counter = (emetteur.counter + iteration) & 0xF
            encrypted_data, sent_counter = emetteur.send(data_to_send)
            conn.sendall(encrypted_data.to_bytes(8, 'big'))


if __name__ == "__main__":
    main()
