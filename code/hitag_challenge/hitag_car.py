import socket
from Crypto.Cipher import ARC4
from Crypto.Random import get_random_bytes
import hashlib

class Hitag3Receiver:
    def __init__(self, key):
        """
        Initialise le récepteur Hitag3 avec une clé spécifiée.
        :param key: Clé utilisée pour le chiffrement (doit être de longueur arbitraire, mais sera condensée)
        """
        self.key = hashlib.sha256(key).digest()[:16]  # Utiliser une clé de 128 bits

    def generate_challenge(self):
        """
        Génère un challenge aléatoire.
        :return: Challenge aléatoire
        """
        return get_random_bytes(8)  # Utiliser un challenge de 8 octets pour imiter Hitag3

    def check_answer(self, challenge, answer):
        """
        Vérifie si la réponse chiffrée correspond au challenge initial en utilisant la clé du récepteur.
        :param challenge: Challenge initial
        :param answer: Réponse chiffrée à vérifier
        :return: True si la réponse est correcte, False sinon
        """
        cipher = ARC4.new(self.key)
        expected_response = cipher.encrypt(challenge)
        return answer == expected_response

def main():
    # Génération d'une clé aléatoire partagée
    key = b'same_shared_secret'
    receiver = Hitag3Receiver(key)

    # Initialisation du serveur
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('localhost', 65432))
        s.listen()

        print("Serveur en attente de connexion...")

        # Acceptation de la connexion d'un client
        conn, addr = s.accept()
        with conn:
            print('Connecté par', addr)

            # Génération du challenge
            challenge = receiver.generate_challenge()
            print("Génération du challenge: ", challenge.hex())

            # Envoi du challenge au client
            conn.sendall(challenge)

            # Réception de la réponse du client
            response = conn.recv(1024)
            print("Réponse reçue: ", response.hex())

            # Vérification de la réponse
            if receiver.check_answer(challenge, response):
                print("Authentication successful")
            else:
                print("Authentication failed")

if __name__ == "__main__":
    main()
