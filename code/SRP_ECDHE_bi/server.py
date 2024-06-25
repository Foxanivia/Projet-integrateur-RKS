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

def create_salted_verification_key(username, password):
    salt, vkey = srp.create_salted_verification_key(username, password)
    salt_encoded = base64.b64encode(salt).decode('utf-8')
    return salt_encoded, vkey

def create_server_verifier(username, salt_encoded, vkey, A_encoded):
    salt = base64.b64decode(salt_encoded)
    A = base64.b64decode(A_encoded)
    svr = srp.Verifier(username, salt, vkey, A)
    s, B = svr.get_challenge()
    s_encoded = base64.b64encode(s).decode('utf-8')
    B_encoded = base64.b64encode(B).decode('utf-8')
    return svr, s_encoded, B_encoded

def verify_session_on_server(svr, M_encoded):
    M = base64.b64decode(M_encoded)
    HAMK = svr.verify_session(M)
    HAMK_encoded = base64.b64encode(HAMK).decode('utf-8')
    return HAMK_encoded

def send_to_client(conn, data):
    conn.sendall(json.dumps(data).encode('utf-8'))

def receive_from_client(conn):
    data = conn.recv(4096)
    return json.loads(data.decode('utf-8'))

def main():
    username = 'testuser'
    password = 'testpassword'

    #print("Creating salted verification key...")
    salt_encoded, vkey = create_salted_verification_key(username, password)
    #print("Salt and verification key created.")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('0.0.0.0', 8080))
        s.listen()
        #print("Server is listening on port 8080...")
        conn, addr = s.accept()
        with conn:
            #print(f"Connected by {addr}")

            # Phase ECDHE
            #print("Receiving client public key...")
            client_data = receive_from_client(conn)
            client_public_key_pem = client_data['client_public_key']
            peer_client_public_key = deserialize_public_key(client_public_key_pem.encode('utf-8'))

            #print("Generating server key pair...")
            server_private_key, server_public_key = generate_key_pair()
            serialized_server_public_key = serialize_public_key(server_public_key)

            #print("Deriving shared key on server...")
            shared_key_server = derive_shared_key(server_private_key, peer_client_public_key)
            serialized_shared_key_server = base64.b64encode(shared_key_server).decode('utf-8')

            #print("Sending server public key to client...")
            send_to_client(conn, {'server_public_key': serialized_server_public_key.decode('utf-8')})

            #print("Receiving client shared key for verification...")
            client_data = receive_from_client(conn)
            serialized_shared_key_client = client_data['shared_key_client']

            #print("Sending server shared key to client for verification...")
            send_to_client(conn, {'shared_key_server': serialized_shared_key_server})

            assert serialized_shared_key_client == serialized_shared_key_server, "Shared keys do not match!"
            #print("Shared keys match. ECDHE verification completed.")

            # Phase SRP
            #print("Receiving data from client...")
            client_data = receive_from_client(conn)
            uname = client_data['username']
            A_encoded = client_data['A']

            #print("Creating server verifier...")
            svr, s_encoded, B_encoded = create_server_verifier(uname, salt_encoded, vkey, A_encoded)
            #print(f"Server verifier created. Salt: {s_encoded}, B: {B_encoded}")

            if s_encoded is None or B_encoded is None:
                raise AuthenticationFailed()

            #print("Sending challenge to client...")
            send_to_client(conn, {'s': s_encoded, 'B': B_encoded})

            #print("Receiving M from client...")
            client_data = receive_from_client(conn)
            M_encoded = client_data['M']

            if M_encoded is None:
                raise AuthenticationFailed()

            #print("Verifying session on server...")
            HAMK_encoded = verify_session_on_server(svr, M_encoded)
            #print(f"Session verified on server. HAMK: {HAMK_encoded}")

            #print("Sending HAMK to client...")
            send_to_client(conn, {'HAMK': HAMK_encoded})

            #print("Authentication process completed.")
            if svr.authenticated():
                #print("Server is authenticated.")
                pass
            else:
                raise AuthenticationFailed()

if __name__ == '__main__':
    main()
