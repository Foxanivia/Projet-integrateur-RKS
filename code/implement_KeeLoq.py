
class Keeloq:
    def __init__(self, key):
        self.key = key

    def _nlfsr(self, state):
        return ((state >> 0) ^ (state >> 2) ^ (state >> 3) ^ (state >> 5) ^ (state >> 7) ^ (state >> 10) ^
                (state >> 11) ^ (state >> 13) ^ (state >> 14) ^ (state >> 15) ^ (state >> 17) ^ (state >> 19) ^
                (state >> 22) ^ (state >> 24) ^ (state >> 26) ^ (state >> 28)) & 1

    def _feistel(self, data, round_key):
        result = 0
        for i in range(32):
            lfsr_output = self._nlfsr(round_key)
            bit = ((data >> i) & 1) ^ lfsr_output
            result |= (bit << i)
            round_key >>= 1
            round_key |= (bit << 63)
        return result

    def encrypt(self, data, counter):
        data = ((counter & 0xF) << 28) | (data & 0x0FFFFFFF)  # Inclure le compteur de 4 bits dans les 4 bits de poids forts
        for round in range(528):
            round_key = (self.key >> (round % 64)) & 0xFFFFFFFF
            data = self._feistel(data, round_key)
        return data

    def decrypt(self, data):
        for round in range(528):
            round_key = (self.key >> ((527 - round) % 64)) & 0xFFFFFFFF
            data = self._feistel(data, round_key)
        counter = (data >> 28) & 0xF  # Extraire les 4 bits de poids forts comme le compteur
        decrypted_data = data & 0x0FFFFFFF  # Extraire les 28 bits de poids faibles comme les données
        return decrypted_data, counter


class Emetteur:
    def __init__(self, key):
        self.keeloq = Keeloq(key)
        self.counter = 0  # Compteur initial

    def send(self, data):
        self.counter = (self.counter + 1) & 0xF  # Incrémenter le compteur sur 4 bits pour chaque envoi
        encrypted_data = self.keeloq.encrypt(data, self.counter)
        return encrypted_data, self.counter


class Recepteur:
    def __init__(self, key):
        self.keeloq = Keeloq(key)
        self.last_counter = 0  # Dernier compteur connu

    def receive(self, encrypted_data):
        for i in range(6):  # Vérifier les 5 prochains codes possibles
            test_counter = (self.last_counter + i) & 0xF
            test_data, counter = self.keeloq.decrypt(encrypted_data)
            if counter == test_counter:
                self.last_counter = test_counter
                return test_data, True
        return None, False


def main():
    key = 0x1A2B3C4D5E6F7890
    emetteur = Emetteur(key)
    recepteur = Recepteur(key)

    # Exemple 1 : Resynchronisation possible
    print("Exemple 1 : Resynchronisation possible")
    data_to_send = 0x1234567

    # Émetteur envoie les données
    encrypted_data, sent_counter = emetteur.send(data_to_send)
    print(f"Émetteur :")
    print(f" - Données chiffrées envoyées = {hex(encrypted_data)}")
    print(f" - Compteur = {sent_counter}")

    # Récepteur reçoit les données
    received_data, is_valid = recepteur.receive(encrypted_data)
    if received_data is not None:
        print(f"Récepteur :")
        print(f" - Données reçues = {hex(received_data)}")
        print(f" - Valides = {is_valid}")
    else:
        print(f"Récepteur : réception échouée, données invalides")

    # Émetteur saute 3 itérations
    emetteur.counter = (emetteur.counter + 3) & 0xF

    # Émetteur envoie à nouveau les données
    encrypted_data, sent_counter = emetteur.send(data_to_send)
    print(f"Émetteur :")
    print(f" - Données chiffrées envoyées = {hex(encrypted_data)}")
    print(f" - Compteur = {sent_counter}")

    # Récepteur reçoit les données
    received_data, is_valid = recepteur.receive(encrypted_data)
    if received_data is not None:
        print(f"Récepteur :")
        print(f" - Données reçues = {hex(received_data)}")
        print(f" - Valides = {is_valid}")
    else:
        print(f"Récepteur : réception échouée, données invalides")

    # Vérification
    if is_valid and received_data == data_to_send:
        print("Échange réussi : les données sont valides et correspondantes.")
    else:
        print("Échange échoué : les données ne sont pas valides ou ne correspondent pas.")
    print()

    # Exemple 2 : Resynchronisation impossible
    print("Exemple 2 : Resynchronisation impossible")
    data_to_send = 0x1234567

    # Émetteur envoie les données
    encrypted_data, sent_counter = emetteur.send(data_to_send)
    print(f"Émetteur :")
    print(f" - Données chiffrées envoyées = {hex(encrypted_data)}")
    print(f" - Compteur = {sent_counter}")

    # Récepteur reçoit les données
    received_data, is_valid = recepteur.receive(encrypted_data)
    if received_data is not None:
        print(f"Récepteur :")
        print(f" - Données reçues = {hex(received_data)}")
        print(f" - Valides = {is_valid}")
    else:
        print(f"Récepteur : réception échouée, données invalides")

    # Émetteur saute 6 itérations
    emetteur.counter = (emetteur.counter + 6) & 0xF

    # Émetteur envoie à nouveau les données
    encrypted_data, sent_counter = emetteur.send(data_to_send)
    print(f"Émetteur :")
    print(f" - Données chiffrées envoyées = {hex(encrypted_data)}")
    print(f" - Compteur = {sent_counter}")

    # Récepteur reçoit les données
    received_data, is_valid = recepteur.receive(encrypted_data)
    if received_data is not None:
        print(f"Récepteur :")
        print(f" - Données reçues = {hex(received_data)}")
        print(f" - Valides = {is_valid}")
    else:
        print(f"Récepteur : réception échouée, données invalides")

    # Vérification
    if is_valid and received_data == data_to_send:
        print("Échange réussi : les données sont valides et correspondantes.")
    else:
        print("Échange échoué : les données ne sont pas valides ou ne correspondent pas.")
    print()


if __name__ == "__main__":
    main()
