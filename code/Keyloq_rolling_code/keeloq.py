class Keeloq:
    def __init__(self, key: int):
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

    def decrypt(self, data: int):
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
