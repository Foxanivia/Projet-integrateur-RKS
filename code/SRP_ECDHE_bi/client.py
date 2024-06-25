import srp
import socket
import json
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class AuthenticationFailed(Exception):
    """Exception levée en cas d'échec de l'authentification."""
    pass

# Utilitaires pour ECDHE
def generate_key_pair():
    """
    Génère une paire de clés (privée et publique) ECDHE.

    Courbe elliptique utilisée : SECP256R1 (alias P-256)
    - Cette courbe est définie par l'équation : y^2 = x^3 + ax + b mod p
    - Paramètres de la courbe SECP256R1 :
      - p (le module) : un grand nombre premier
      - a et b : coefficients de l'équation de la courbe
      - G (le générateur) : un point de base (xG, yG) sur la courbe
      - n : l'ordre de G (le nombre de points sur la courbe)

    La clé privée est un entier aléatoire d (0 < d < n). La clé publique est un point Q = d * G,
    où la multiplication est la multiplication scalaire sur la courbe elliptique.
    """
    private_key = ec.generate_private_key(ec.SECP256R1())  # d (clé privée)
    public_key = private_key.public_key()  # Q = d * G (clé publique)
    return private_key, public_key

def serialize_public_key(public_key):
    """
    Sérialise une clé publique en format PEM.

    La clé publique est un point sur la courbe elliptique, souvent représenté en coordonnées (x, y).
    La sérialisation convertit ce point en un format standardisé pour échange.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(pem_data):
    """
    Désérialise une clé publique à partir du format PEM.

    La désérialisation convertit les données PEM en un point (x, y) sur la courbe elliptique.
    """
    return serialization.load_pem_public_key(pem_data)

def derive_shared_key(private_key, peer_public_key):
    """
    Dérive une clé partagée à partir d'une clé privée et d'une clé publique d'un pair.

    Mathématiquement, si le client possède une clé privée d_C et le serveur une clé privée d_S, et que les clés publiques
    correspondantes sont Q_C = d_C * G et Q_S = d_S * G (où G est un générateur sur la courbe), alors la clé partagée
    est S = d_C * Q_S = d_S * Q_C, qui est un point sur la courbe elliptique. Le KDF (HKDF ici) est utilisé pour 
    dériver une clé symétrique à partir de ce point partagé.
    """
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data'
    ).derive(shared_key)

def start_user_authentication(username, password):
    usr = srp.User(username, password)
    uname, A = usr.start_authentication()
    A_encoded = base64.b64encode(A).decode('utf-8')
    return usr, uname, A_encoded

def process_server_challenge(usr, s_encoded, B_encoded):
    s = base64.b64decode(s_encoded)
    B = base64.b64decode(B_encoded)
    M = usr.process_challenge(s, B)
    M_encoded = base64.b64encode(M).decode('utf-8')
    return M_encoded

def verify_session_on_client(usr, hamk_encoded):
    hamk = base64.b64decode(hamk_encoded)
    usr.verify_session(hamk)

def send_to_server(conn, data):
    conn.sendall(json.dumps(data).encode('utf-8'))

def receive_from_server(conn):
    data = conn.recv(4096)
    return json.loads(data.decode('utf-8'))

def main():
    username = 'testuser'
    password = 'testpassword'

    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect(('169.254.36.137', 8080))

    try:
        # Phase ECDHE
        print("Generating client key pair...")
        client_private_key, client_public_key = generate_key_pair()
        serialized_client_public_key = serialize_public_key(client_public_key)

        print("Sending client public key to server...")
        send_to_server(conn, {'client_public_key': serialized_client_public_key.decode('utf-8')})

        print("Receiving server public key...")
        server_data = receive_from_server(conn)
        server_public_key_pem = server_data['server_public_key']
        peer_server_public_key = deserialize_public_key(server_public_key_pem.encode('utf-8'))

        print("Deriving shared key on client...")
        shared_key_client = derive_shared_key(client_private_key, peer_server_public_key)
        serialized_shared_key_client = base64.b64encode(shared_key_client).decode('utf-8')

        print("Sending client shared key to server for verification...")
        send_to_server(conn, {'shared_key_client': serialized_shared_key_client})

        print("Receiving server shared key for verification...")
        server_data = receive_from_server(conn)
        serialized_shared_key_server = server_data['shared_key_server']

        assert serialized_shared_key_client == serialized_shared_key_server, "Shared keys do not match!"
        print("Shared keys match. ECDHE verification completed.")

        # Phase SRP
        print("Starting user authentication...")
        usr, uname, A_encoded = start_user_authentication(username, password)
        print(f"User authentication started. Username: {uname}, A: {A_encoded}")

        print("Sending username and A to server...")
        send_to_server(conn, {'username': uname, 'A': A_encoded})

        print("Receiving challenge from server...")
        server_data = receive_from_server(conn)
        s_encoded = server_data['s']
        B_encoded = server_data['B']

        if s_encoded is None or B_encoded is None:
            raise AuthenticationFailed()

        print("Processing server challenge...")
        M_encoded = process_server_challenge(usr, s_encoded, B_encoded)
        print(f"Challenge processed. M: {M_encoded}")

        if M_encoded is None:
            raise AuthenticationFailed()

        print("Sending M to server...")
        send_to_server(conn, {'M': M_encoded})

        print("Receiving HAMK from server...")
        server_data = receive_from_server(conn)
        HAMK_encoded = server_data['HAMK']

        if HAMK_encoded is None:
            raise AuthenticationFailed()

        print("Verifying session on client...")
        verify_session_on_client(usr, HAMK_encoded)
        print("Session verified on client.")

        print("Authentication process completed.")
        if usr.authenticated():
            print("Client is authenticated.")
        else:
            raise AuthenticationFailed()
    finally:
        conn.close()

if __name__ == '__main__':
    main()
