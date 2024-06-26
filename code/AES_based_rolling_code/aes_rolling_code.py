from Crypto.Cipher import AES

class AESRollingCode:
    def __init__(self, key: bytes, iterations: int = 5):
        """
        Initialisation d'un émetteur/récepteur de code roulant
        :param key:        Clé secrète partagé
        :param iterations: Tolérance à la desynchronisation
        """
        self.key = key
        self.iterations = iterations
        self.counter = 0
        self.current_code = self.__generate_code()
        self.future_codes = self.__generate_future_codes()

    def __generate_code(self, counter: int = None):
        """
        Génère un code roulant à partir du compteur et de la clé secrète
        :param counter: Compteur du code à générer
        :return: Renvoie le nouveau code généré
        """
        if counter is None:
            counter = self.counter
        cipher = AES.new(self.key, AES.MODE_ECB)
        code = cipher.encrypt(counter.to_bytes(16, byteorder='big'))
        return int.from_bytes(code, byteorder='big')

    def __generate_future_codes(self):
        """
        Génère les futures codes roulant pour la fenêtre de tolérance
        :return: Renvoie la liste des futurs codes roulant
        """
        future_codes = []
        for i in range(1, self.iterations + 1):
            future_codes.append(self.__generate_code(self.counter + i))
        return future_codes

    def __resynchronize(self, received_code: int):
        """
        Resynchronise les codes roulants avec le code roulant reçu
        :param received_code: Code sur le quel se resynchroniser
        """
        self.current_code = received_code
        self.counter += self.future_codes.index(received_code) + 1
        self.future_codes = self.__generate_future_codes()

    def increment_code(self):
        """
        Incrémente le compteur et met l'ensemble des code roulants de la classe à jour
        """
        self.counter += 1
        self.current_code = self.__generate_code()
        self.future_codes = self.__generate_future_codes()

    def get_current_code(self):
        """
        :return: Renvoie le code roulant courant
        """
        return self.current_code

    def compare_code(self, received_code: int):
        """
        Compare et gère la desynchronisation
        :param received_code: Code reçu
        :return: Renvoie si les codes sont synchronisé (True) ou non (False)
        """
        if received_code == self.current_code:
            self.increment_code()
            return True
        elif received_code in self.future_codes:
            self.__resynchronize(received_code)
            return True
        return False
