import socket
from keeloq import Keeloq


class Recepteur:
    def __init__(self, key: int):
        """
        Initialise une instance de la classe Recepteur avec une clé donnée.
        :param key: Clé de chiffrement utilisée pour initialiser l'instance Keeloq.
        """
        self.keeloq = Keeloq(key)
        self.last_counter = 0  # Dernier compteur connu

    def receive(self, encrypted_data: int):
        """
        Déchiffre les données chiffrées reçues et vérifie le compteur.
        :param encrypted_data: Les données chiffrées reçues.
        :return: Les données déchiffrées et un booléen indiquant si le compteur est valide.
        """
        for i in range(6):  # Vérifier les 5 prochains codes possibles
            test_counter = (self.last_counter + i) & 0xF
            test_data, counter = self.keeloq.decrypt(encrypted_data)
            if counter == test_counter:
                self.last_counter = test_counter
                return test_data, True
        return None, False


def main():
    key = int(input("Veuillez entrer la clé (en entier): "))
    recepteur = Recepteur(key)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('localhost', 12345))

        # Ex1: Initialisation à temps 0
        print("Initialisation :")
        encrypted_data = s.recv(8)
        encrypted_data = int.from_bytes(encrypted_data, 'big')
        received_data, is_valid = recepteur.receive(encrypted_data)
        print(" == RECEPTEUR == ")
        if received_data is not None:
            print(f"•Code déchiffré reçu : {received_data}")
            print(f"•Etat                : {is_valid}")
        else:
            print("Réception échouée, données invalides")

        # Ex2: Resynchronisation, après une désynchronisation tolérable
        print("Désynchronisation tolérable :")
        encrypted_data = s.recv(8)
        encrypted_data = int.from_bytes(encrypted_data, 'big')
        received_data, is_valid = recepteur.receive(encrypted_data)
        print(" == RECEPTEUR == ")
        if received_data is not None:
            print(f"•Code déchiffré reçu : {received_data}")
            print(f"•Etat                : {is_valid}")
        else:
            print("Réception échouée, données invalides")

        # Ex3: Resynchronisation, après une désynchronisation non-tolérable
        print("Désynchronisation non-tolérable :")
        encrypted_data = s.recv(8)
        encrypted_data = int.from_bytes(encrypted_data, 'big')
        received_data, is_valid = recepteur.receive(encrypted_data)
        print(" == RECEPTEUR == ")
        if received_data is not None:
            print(f"•Code déchiffré reçu : {received_data}")
            print(f"•Etat                : {is_valid}")
        else:
            print("Réception échouée, données invalides")


if __name__ == "__main__":
    main()
