import hashlib
from secrets import randbelow
from ecdsa import SECP256k1, SigningKey, VerifyingKey
import socket

# Paramètres SRP
N = int("E0A67598EAF6F9D3B0542A6BCF209B91E9D0A9AE8567C40941BA19C40CF7434F"
        "A9A91FD95F5A1FBB5B1A3945135B1F8E1A7A3EBF00A4D4B2F11A6157E1B18F15"
        "1D8E21D0E56FA1D64BFDF3E1D7BC7A25A204F0E8A3E2B6D32530FF2EFD86D6F6", 16)
g = 2

# Paramètres utilisateur
username = 'coco'
password = 'gateau145'

# Génération de sel et calcul du vérificateur
salt = randbelow(1 << 256)
xH = hashlib.sha256(f"{salt}{password}".encode()).hexdigest()
x = int(xH, 16)
v = pow(g, x, N)

# Génération de la clé privée et publique éphémère
a = randbelow(N)
A = pow(g, a, N)

# Génération de la paire de clés ECDHE
ecdhe_private_key = SigningKey.generate(curve=SECP256k1)
ecdhe_public_key = ecdhe_private_key.get_verifying_key()

# Envoi des paramètres au serveur
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 65435)
sock.connect(server_address)

try:
    message = f"{A},{ecdhe_public_key.to_string().hex()},{salt}"
    sock.sendall(message.encode())

    # Réception des paramètres du serveur
    data = sock.recv(1024)
    B, ecdhe_public_key_server_hex = data.decode().split(',')
    B = int(B)
    ecdhe_public_key_server = VerifyingKey.from_string(bytes.fromhex(ecdhe_public_key_server_hex), curve=SECP256k1)

    # Calcul des paramètres de l'authentification
    uH = hashlib.sha256(f"{A}{B}".encode()).hexdigest()
    u = int(uH, 16)
    S_user = pow(B - 3 * v, a + u * x, N)
    K_user = hashlib.sha256(str(S_user).encode()).digest()

    # Preuve de l'authentification
    N_hash = hashlib.sha256(str(N).encode()).hexdigest()
    g_hash = hashlib.sha256(str(g).encode()).hexdigest()
    I_hash = hashlib.sha256(username.encode()).hexdigest()
    M_user = hashlib.sha256(f"{N_hash}^{g_hash}|{I_hash}|{salt}|{A}|{B}|{K_user.hex()}".encode()).hexdigest()
    sock.sendall(M_user.encode())

    # Réception de la preuve du serveur
    M_server = sock.recv(1024).decode()
    M_check = hashlib.sha256(f"{A}|{M_user}|{K_user.hex()}".encode()).hexdigest()

    if M_server == M_check:
        print("Authentification réussie")
    else:
        print("Échec de l'authentification")
finally:
    sock.close()
