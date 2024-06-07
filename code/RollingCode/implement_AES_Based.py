# Bibliothèques
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


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


def show_compared_code(emitter, receiver, stage):
    """
    Affichage pour la comparaison du code
    :param emitter:
    :param receiver:
    :param stage:
    :return:
    """
    print(f"{stage} :")
    print(f"• Code courant émetteur  : {emitter.get_current_code()}")
    print(f"• Code courant récepteur : {receiver.get_current_code()}\n")


def main():
    # Génération d'une clé aléatoire partagée
    key = get_random_bytes(16)

    # Création de l'émetteur et du récepteur qui partagent la même clé
    emitter = AESRollingCode(key)
    receiver = AESRollingCode(key)

    #################################
    # Ex1: Initialisation à temps 0 #
    #################################
    show_compared_code(emitter, receiver, "Initialisation ")
    print("Les codes correspondent à temps 0.\n\n" + "-" * 30+"\n")

    ##################################################################
    # Ex2: Resynchronisation, après une désynchronisation tolérable  #
    ##################################################################
    print("Désynchronisation tolérable  :")
    iteration = 3
    print(f"# Incrementation de l'émetteur sans reception x{iteration}")
    for _ in range(iteration):
        emitter.increment_code()  # Émetteur génère quelques codes sans envoyer

    show_compared_code(emitter, receiver, "-Avant resynchronisation")

    emitted_code = emitter.get_current_code()
    if receiver.compare_code(emitted_code):
        print("Le récepteur a pu resynchroniser avec succès.\n")
    else:
        print("Le récepteur n'a pas pu resynchroniser.\n")

    show_compared_code(emitter, receiver, "-Après resynchronisation")
    print("-" * 30+"\n")

    ######################################################################
    # Ex3: Resynchronisation, après une désynchronisation non-tolérable  #
    ######################################################################
    print("Desynchronisation non-tolérable :")
    iteration = 6
    print(f"# Incrementation de l'émetteur sans reception x{iteration}")
    for _ in range(iteration):
        emitter.increment_code()

    show_compared_code(emitter, receiver, "-Avant tentative de resynchronisation")

    emitted_code = emitter.get_current_code()
    if receiver.compare_code(emitted_code):
        print("Le récepteur a pu resynchroniser avec succès.\n")
    else:
        print("Le récepteur n'a pas pu resynchroniser.\n")

    show_compared_code(emitter, receiver, "-Après tentative de resynchronisation")
    print("-" * 30+"\n")


if __name__ == "__main__":
    main()
