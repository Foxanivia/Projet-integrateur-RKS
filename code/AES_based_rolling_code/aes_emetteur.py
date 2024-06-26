import socket
from Crypto.Random import get_random_bytes
from aes_rolling_code import AESRollingCode


def main():
    # Demander à l'utilisateur d'entrer la clé
    key = get_random_bytes(16)
    print(f"La clé générée est : {key.hex()}")

    emitter = AESRollingCode(key)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('localhost', 12345))
        s.listen()
        print("Emetteur en attente de connexion...")
        conn, addr = s.accept()
        with conn:
            print('Connecté par', addr)

            # Ex1: Initialisation à temps 0
            print("Initialisation :")
            emitted_code = emitter.get_current_code()
            conn.sendall(emitted_code.to_bytes(16, 'big'))

            # Ex2: Resynchronisation, après une désynchronisation tolérable
            print("Désynchronisation tolérable :")
            iteration = 3
            print(f"Incrementation de l'émetteur sans reception x{iteration}")
            for _ in range(iteration):
                emitter.increment_code()
            emitted_code = emitter.get_current_code()
            conn.sendall(emitted_code.to_bytes(16, 'big'))

            # Ex3: Resynchronisation, après une désynchronisation non-tolérable
            print("Désynchronisation non-tolérable :")
            iteration = 6
            print(f"Incrementation de l'émetteur sans reception x{iteration}")
            for _ in range(iteration):
                emitter.increment_code()
            emitted_code = emitter.get_current_code()
            conn.sendall(emitted_code.to_bytes(16, 'big'))


if __name__ == "__main__":
    main()
