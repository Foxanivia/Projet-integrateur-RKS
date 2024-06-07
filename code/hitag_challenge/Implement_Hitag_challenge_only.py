# Bibliothèques
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
    key = b'secret_key'

    # Création de l'émetteur et du récepteur qui partagent la même clé
    transponder = Hitag3Transponder(key)
    receiver = Hitag3Receiver(key)

    #################################
    # Ex1: Echange de Challenge     #
    #################################

    # Le récepteur génère un défi
    challenge = receiver.generate_challenge()
    print("Génération d'un challenge: ")
    print(f"• Challenge: {challenge.hex()}\n")

    # Le transpondeur chiffre le défi et envoie la réponse
    response = transponder.chiffre_challenge(challenge)
    print("Chiffre le challenge et le renvoie: ")
    print(f"• Answer   : {response.hex()}\n")

    # Vérification par le receveur de la réponse
    print("Vérification de la paire Challenge/Réponse: ")
    # Le récepteur vérifie la réponse
    if receiver.check_answer(challenge, response):
        print("Authentication successful")
    else:
        print("Authentication failed")


if __name__ == "__main__":
    main()
