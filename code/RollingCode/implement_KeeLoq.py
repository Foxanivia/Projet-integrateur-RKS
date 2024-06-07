import random


class Keeloq:
    def __init__(self, key):
        """
        Initialise une instance de la classe Keeloq avec une clé donnée.
        :param key: Clé de chiffrement utilisée pour les opérations Keeloq.
        """
        self.key = key

    @staticmethod
    def __nlfsr(state):
        """
        Effectue une opération de registre à décalage linéaire rétrograde non linéaire (NLFSR) sur un état donné.
        :param state: L'état initial du NLFSR.
        :return: Le bit résultant de l'opération NLFSR.
        """
        return ((state >> 0) ^ (state >> 2) ^ (state >> 3) ^ (state >> 5) ^ (state >> 7) ^ (state >> 10) ^
                (state >> 11) ^ (state >> 13) ^ (state >> 14) ^ (state >> 15) ^ (state >> 17) ^ (state >> 19) ^
                (state >> 22) ^ (state >> 24) ^ (state >> 26) ^ (state >> 28)) & 1

    def __feistel(self, data, round_key):
        """
        Effectue une opération de 32 tour de Feistel (modifié) sur les données.
        :param data: Les données à transformer.
        :param round_key: La clé de ronde utilisée pour l'opération Feistel.
        :return: Les données transformées après l'opération Feistel.
        """
        result = 0
        for i in range(32):
            lfsr_output = self.__nlfsr(round_key)
            bit = ((data >> i) & 1) ^ lfsr_output
            result |= (bit << i)
            round_key >>= 1
            round_key |= (bit << 63)
        return result

    def encrypt(self, data: int, counter: int):
        """
        Chiffre les données données en utilisant un compteur et la clé de l'instance Keeloq.
        :param data: Les données à chiffrer.
        :param counter: Le compteur à inclure dans le chiffrement.
        :return: Les données chiffrées.
        """
        data = ((counter & 0xF) << 28) | (data & 0x0FFFFFFF)  # Inclure le compteur de 4 bits dans les 4 bits de poids forts
        for round in range(528):
            round_key = (self.key >> (round % 64)) & 0xFFFFFFFF
            data = self.__feistel(data, round_key)
        return data

    def decrypt(self, data: bytes):
        """
        Déchiffre les données données en utilisant la clé de l'instance Keeloq.
        :param data: Les données à déchiffrer.
        :return: Les données déchiffrées et le compteur extrait.
        """
        for round in range(528):
            round_key = (self.key >> ((527 - round) % 64)) & 0xFFFFFFFF
            data = self.__feistel(data, round_key)
        counter = (data >> 28) & 0xF  # Extraire les 4 bits de poids forts comme le compteur
        decrypted_data = data & 0x0FFFFFFF  # Extraire les 28 bits de poids faibles comme les données
        return decrypted_data, counter


class Emetteur:
    def __init__(self, key:bytes):
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


class Recepteur:
    def __init__(self, key: bytes):
        """
        Initialise une instance de la classe Recepteur avec une clé donnée.
        :param key: Clé de chiffrement utilisée pour initialiser l'instance Keeloq.
        """
        self.keeloq = Keeloq(key)
        self.last_counter = 0  # Dernier compteur connu

    def receive(self, encrypted_data: bytes):
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


def comparaison(emetteur: Emetteur, recepteur: Recepteur, data_to_send: bytes):
    """
    Compare les données envoyées par l'émetteur et les données reçues par le récepteur.
    :param emetteur: Instance de la classe Emetteur.
    :param recepteur: Instance de la classe Recepteur.
    :param data_to_send: Les données à envoyer et à comparer.
    :return: None
    """
    encrypted_data, sent_counter = emetteur.send(data_to_send)
    received_data, is_valid = recepteur.receive(encrypted_data)

    print(" == EMETTEUR == ")
    print(f"•Compteur            : {sent_counter}")
    print(f"•Code chiffré envoyé : {encrypted_data}\n")

    print(" == RECEPTEUR == ")
    if received_data is not None:
        print(f"•Code déchiffré reçu : {received_data}")
        print(f"•Etat                : {is_valid}")
    else:
        print(f"Récepteur : réception échouée, données invalides")

    print("\n"+"-" * 30 + "\n")


def main():
    # Génération d'une clé aléatoire partagée de 64 Bits
    key = random.getrandbits(64)

    # Création de l'émetteur et du récepteur qui partagent la même clé
    emetteur = Emetteur(key)
    recepteur = Recepteur(key)

    data_to_send = 0x1234567

    #################################
    # Ex1: Initialisation à temps 0 #
    #################################
    print("Initialisation :")
    comparaison(emetteur, recepteur, data_to_send)

    ##################################################################
    # Ex2: Resynchronisation, après une désynchronisation tolérable  #
    ##################################################################
    print("Désynchronisation tolérable  :")
    iteration = 3
    print(f"# Incrementation de l'émetteur sans reception x{iteration}")
    emetteur.counter = (emetteur.counter + iteration) & 0xF
    comparaison(emetteur, recepteur, data_to_send)


    ######################################################################
    # Ex3: Resynchronisation, après une désynchronisation non-tolérable  #
    ######################################################################
    print("Désynchronisation non-tolérable  :")
    iteration = 6
    print(f"# Incrementation de l'émetteur sans reception x{iteration}")
    emetteur.counter = (emetteur.counter + iteration) & 0xF
    comparaison(emetteur, recepteur, data_to_send)


if __name__ == "__main__":
    main()
