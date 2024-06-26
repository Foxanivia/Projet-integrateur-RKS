import hashlib
from secrets import randbelow
from ecdsa import SECP256k1, SigningKey, VerifyingKey
import socket

# Paramètres SRP
N = int("E0A67598EAF6F9D3B0542A6BCF209B91E9D0A9AE8567C40941BA19C40CF7434F"
        "A9A91FD95F5A1FBB5B1A3945135B1F8E1A7A3EBF00A4D4B2F11A6157E1B18F15"
        "1D8E21D0E56FA1D64BFDF3E1D7BC7A25A204F0E8A3E2B6D32530FF2EFD86D6F6", 16)
g = 2
k = 3  # Constante SRP

# Configuration du serveur
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 65435)
sock.bind(server_address)
sock.listen(1)

print("Serveur en attente de connexion...")

connection, client_address = sock.accept()

try:
    data = connection.recv(1024)
    if data:
        A, ecdhe_public_key_hex, salt = data.decode().split(',')
        A = int(A)
        salt = int(salt)
        ecdhe_public_key = VerifyingKey.from_string(bytes.fromhex(ecdhe_public_key_hex), curve=SECP256k1)

        # Récupération du vérificateur depuis la base de données
        # Pour cette démonstration, nous le recalculons ici
        password = 'gateau145'
        xH = hashlib.sha256(f"{salt}{password}".encode()).hexdigest()
        x = int(xH, 16)
        v = pow(g, x, N)

        # Génération de la clé privée et publique éphémère
        b = randbelow(N)
        B = (k * v + pow(g, b, N)) % N

        # Génération de la paire de clés ECDHE
        ecdhe_private_key = SigningKey.generate(curve=SECP256k1)
        ecdhe_public_key_server = ecdhe_private_key.get_verifying_key()

        # Envoi des paramètres à l'utilisateur
        message = f"{B},{ecdhe_public_key_server.to_string().hex()}"
        connection.sendall(message.encode())

        # Réception de la preuve de l'utilisateur
        M_user = connection.recv(1024).decode()

        # Calcul des paramètres de l'authentification
        uH = hashlib.sha256(f"{A}{B}".encode()).hexdigest()
        u = int(uH, 16)
        S_server = pow(A * pow(v, u, N), b, N)
        K_server = hashlib.sha256(str(S_server).encode()).digest()

        # Preuve de l'authentification
        N_hash = hashlib.sha256(str(N).encode()).hexdigest()
        g_hash = hashlib.sha256(str(g).encode()).hexdigest()
        I_hash = hashlib.sha256('coco'.encode()).hexdigest()
        M_check = hashlib.sha256(f"{N_hash}^{g_hash}|{I_hash}|{salt}|{A}|{B}|{K_server.hex()}".encode()).hexdigest()

        if M_user == M_check:
            M_server = hashlib.sha256(f"{A}|{M_user}|{K_server.hex()}".encode()).hexdigest()
            connection.sendall(M_server.encode())
            print("Authentification réussie")
        else:
            print("Échec de l'authentification")
finally:
    connection.close()
