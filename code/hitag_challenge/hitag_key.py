import socket
from Crypto.Cipher import ARC4
from Crypto.Random import get_random_bytes
import hashlib

class Hitag3Transponder:
    def __init__(self, key):
        """
        Initialise le transpondeur Hitag3 avec une clé spécifiée.
        :param key: Clé utilisée pour le chiffrement (doit être de longueur arbitraire, mais sera condensée)
        """
        self.key = hashlib.sha256(key).digest()[:16]  # Utiliser une clé de 128 bits

    def chiffre_challenge(self, challenge):
        """
        Chiffre un challenge en utilisant la clé du transpondeur.
        :param challenge: Challenge à chiffrer
        :return: Challenge chiffré
        """
        # Chiffrement par Flux
        cipher = ARC4.new(self.key)
        encrypted_challenge = cipher.encrypt(challenge)
        return encrypted_challenge

def main():
    # Génération d'une clé aléatoire partagée
    key = b'same_shared_secret'
    transponder = Hitag3Transponder(key)

    # Connexion au serveur
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('localhost', 65432))

        # Réception du challenge depuis le serveur
        challenge = s.recv(1024)
        print("Reçu challenge: ", challenge.hex())

        # Chiffrement du challenge
        response = transponder.chiffre_challenge(challenge)
        print("Envoi réponse: ", response.hex())

        # Envoi de la réponse chiffrée au serveur
        s.sendall(response)

if __name__ == "__main__":
    main()
