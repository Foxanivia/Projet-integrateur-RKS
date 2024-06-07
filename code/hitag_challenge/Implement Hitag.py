# Bibliothèques
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib


class HitagTransponder:
    def __init__(self, key):
        """
        Initialise le transpondeur Hitag avec une clé spécifiée.
        :param key: Clé utilisée pour le chiffrement (doit être de longueur arbitraire, mais sera condensée en 128 bits)
        """
        self.key = hashlib.sha256(key).digest()[:16]  # Utiliser une clé de 128 bits

    def chiffre_challenge(self, challenge):
        """
        Chiffre un challenge en utilisant la clé du transpondeur.
        :param challenge: Challenge à chiffrer (doit être de 16 octets)
        :return: Challenge chiffré
        """
        cipher = AES.new(self.key, AES.MODE_ECB)
        encrypted_challenge = cipher.encrypt(challenge)
        return encrypted_challenge


class HitagReceiver:
    def __init__(self, key):
        """
        Initialise le récepteur Hitag avec une clé spécifiée.
        :param key: Clé utilisée pour le chiffrement (doit être de longueur arbitraire, mais sera condensée en 128 bits)
        """
        self.key = hashlib.sha256(key).digest()[:16]  # Utiliser une clé de 128 bits

    def generate_challenge(self):
        """
        Génère un challenge aléatoire de 16 octets.
        :return: Challenge aléatoire
        """
        return get_random_bytes(16)

    def check_answer(self, challenge, anwser):
        """
        Vérifie si la réponse chiffrée correspond au challenge initial en utilisant la clé du récepteur.
        :param challenge: Challenge initial (doit être de 16 octets)
        :param anwser: Réponse chiffrée à vérifier (doit être de 16 octets)
        :return: True si la réponse est correcte, False sinon
        """
        cipher = AES.new(self.key, AES.MODE_ECB)
        expected_response = cipher.encrypt(challenge)
        return anwser == expected_response


def main():
    # Génération d'une clé aléatoire partagée
    key = b'secret_key'

    # Création de l'émetteur et du récepteur qui partagent la même clé
    transponder = HitagTransponder(key)
    receiver = HitagReceiver(key)

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
