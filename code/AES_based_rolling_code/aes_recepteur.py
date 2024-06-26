import socket
from aes_rolling_code import AESRollingCode


def main():
    # Demander à l'utilisateur d'entrer la clé
    key_hex = input("Veuillez entrer la clé (en hexadécimal) : ")
    key = bytes.fromhex(key_hex)

    receiver = AESRollingCode(key)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('localhost', 12345))

        # Ex1: Initialisation à temps 0
        print("Initialisation :")
        encrypted_data = s.recv(16)
        received_code = int.from_bytes(encrypted_data, 'big')
        if receiver.compare_code(received_code):
            print("Le récepteur a pu resynchroniser avec succès.")
        else:
            print("Le récepteur n'a pas pu resynchroniser.")

        # Ex2: Resynchronisation, après une désynchronisation tolérable
        print("Désynchronisation tolérable :")
        encrypted_data = s.recv(16)
        received_code = int.from_bytes(encrypted_data, 'big')
        if receiver.compare_code(received_code):
            print("Le récepteur a pu resynchroniser avec succès.")
        else:
            print("Le récepteur n'a pas pu resynchroniser.")

        # Ex3: Resynchronisation, après une désynchronisation non-tolérable
        print("Désynchronisation non-tolérable :")
        encrypted_data = s.recv(16)
        received_code = int.from_bytes(encrypted_data, 'big')
        if receiver.compare_code(received_code):
            print("Le récepteur a pu resynchroniser avec succès.")
        else:
            print("Le récepteur n'a pas pu resynchroniser.")


if __name__ == "__main__":
    main()
