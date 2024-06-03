from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class AESRollingCode:
    def __init__(self, key, iterations=5):
        self.key = key
        self.iterations = iterations
        self.counter = 0
        self.current_code = self.generate_code()
        self.future_codes = self.generate_future_codes()

    def generate_code(self, counter=None):
        if counter is None:
            counter = self.counter
        cipher = AES.new(self.key, AES.MODE_ECB)
        code = cipher.encrypt(counter.to_bytes(16, byteorder='big'))
        return int.from_bytes(code, byteorder='big')

    def generate_future_codes(self):
        future_codes = []
        for i in range(1, self.iterations + 1):
            future_codes.append(self.generate_code(self.counter + i))
        return future_codes

    def show_current_code(self):
        return self.current_code

    def increment_code(self):
        self.counter += 1
        self.current_code = self.generate_code()
        self.future_codes = self.generate_future_codes()

    def compare_code(self, received_code):
        if received_code == self.current_code:
            self.increment_code()
            return True
        elif received_code in self.future_codes:
            self.resynchronize(received_code)
            return True
        return False

    def resynchronize(self, received_code):
        self.current_code = received_code
        self.counter += self.future_codes.index(received_code) + 1
        self.future_codes = self.generate_future_codes()

def show_compared_code(emitter, receiver, stage):
    print(f"{stage} :")
    print(f"Code courant de l'émetteur : {emitter.show_current_code()}")
    print(f"Code courant du récepteur : {receiver.show_current_code()}\n")

def main():
    key = get_random_bytes(16)

    # Création de l'émetteur et du récepteur avec la même clé
    emitter = AESRollingCode(key)
    receiver = AESRollingCode(key)

    # Montrer le code de base
    print("Code de base :")
    emitted_code = emitter.show_current_code()
    print(f"Code émis initial: {emitted_code}")
    print(f"Code reçu initial: {receiver.show_current_code()}")
    print("Les codes correspondent initialement.\n")
    print("-" * 30)

    # Désynchronisation qui peut être resynchronisée
    print("\nCas de désynchronisation pouvant être resynchronisé :")
    for _ in range(3):
        emitter.increment_code()  # Émetteur génère quelques codes sans envoyer

    show_compared_code(emitter, receiver, "Avant resynchronisation")

    emitted_code = emitter.show_current_code()
    if receiver.compare_code(emitted_code):
        print("Le récepteur a resynchronisé avec succès.")
    else:
        print("Le récepteur n'a pas pu resynchroniser.")

    show_compared_code(emitter, receiver, "Après resynchronisation")
    print("-" * 30)

    # Désynchronisation qui ne peut pas être resynchronisée
    print("\nCas de désynchronisation ne pouvant pas être resynchronisé :")
    for _ in range(6):
        emitter.increment_code()  # Émetteur génère plus de codes que le récepteur ne peut resynchroniser

    show_compared_code(emitter, receiver, "Avant tentative de resynchronisation")

    emitted_code = emitter.show_current_code()
    if receiver.compare_code(emitted_code):
        print("Le récepteur a resynchronisé avec succès.")
    else:
        print("Le récepteur n'a pas pu resynchroniser.")

    show_compared_code(emitter, receiver, "Après tentative de resynchronisation")
    print("-" * 30)

if __name__ == "__main__":
    main()
