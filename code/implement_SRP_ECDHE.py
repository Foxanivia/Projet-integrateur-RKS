import srp
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import time
import psutil

class AuthenticationFailed(Exception):
    """Exception levée en cas d'échec de l'authentification."""
    pass

# Utilitaires pour ECDHE

def generate_key_pair():
    """
    Génère une paire de clés (privée et publique) ECDHE.

    @return: Tuple contenant la clé privée et la clé publique.
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    """
    Sérialise une clé publique en format PEM.

    @param public_key: La clé publique à sérialiser.
    @return: La clé publique sérialisée en format PEM.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(pem_data):
    """
    Désérialise une clé publique à partir du format PEM.

    @param pem_data: Les données PEM de la clé publique.
    @return: La clé publique désérialisée.
    """
    return serialization.load_pem_public_key(pem_data)

def derive_shared_key(private_key, peer_public_key):
    """
    Dérive une clé partagée à partir d'une clé privée et d'une clé publique d'un pair.

    @param private_key: La clé privée.
    @param peer_public_key: La clé publique du pair.
    @return: La clé partagée dérivée.
    """
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data'
    ).derive(shared_key)

def measure_performance(func):
    """
    Mesure la performance en termes de temps et de consommation énergétique d'une fonction.

    @param func: La fonction à mesurer.
    @return: Le résultat de la fonction exécutée.
    """
    def wrapper(*args, **kwargs):
        start_time = time.time()
        start_energy = psutil.sensors_battery().percent
        result = func(*args, **kwargs)
        end_time = time.time()
        end_energy = psutil.sensors_battery().percent
        print(f"Time taken by {func.__name__}: {end_time - start_time} seconds")
        print(f"Energy consumed by {func.__name__}: {start_energy - end_energy} %")
        return result
    return wrapper

@measure_performance
def authentication_process():
    """
    Effectue le processus complet d'authentification en utilisant SRP et ECDHE.
    """
    # ~~~ Initialisation ~~~
    print("Creating salted verification key...")
    salt, vkey = srp.create_salted_verification_key('testuser', 'testpassword')
    print("Salt and verification key created.")

    # ~~~ Begin Authentication ~~~

    print("Starting user authentication...")
    usr = srp.User('testuser', 'testpassword')
    uname, A = usr.start_authentication()
    print(f"User authentication started. Username: {uname}, A: {A}")

    print("Creating server verifier...")
    svr = srp.Verifier(uname, salt, vkey, A)
    s, B = svr.get_challenge()
    print(f"Server verifier created. Salt: {s}, B: {B}")

    if s is None or B is None:
        raise AuthenticationFailed()

    # Client => Server: username, A, client_public_key
    client_private_key, client_public_key = generate_key_pair()
    serialized_client_public_key = serialize_public_key(client_public_key)

    print("Processing server challenge...")
    M = usr.process_challenge(s, B)
    print(f"Challenge processed. M: {M}")

    if M is None:
        raise AuthenticationFailed()

    # Server => Client: s, B, server_public_key
    server_private_key, server_public_key = generate_key_pair()
    serialized_server_public_key = serialize_public_key(server_public_key)

    # Client processes server public key
    peer_server_public_key = deserialize_public_key(serialized_server_public_key)
    shared_key_client = derive_shared_key(client_private_key, peer_server_public_key)

    # Client => Server: M, serialized_client_public_key
    print("Verifying session on server...")
    HAMK = svr.verify_session(M)
    print(f"Session verified on server. HAMK: {HAMK}")

    if HAMK is None:
        raise AuthenticationFailed()

    # Server processes client public key
    peer_client_public_key = deserialize_public_key(serialized_client_public_key)
    shared_key_server = derive_shared_key(server_private_key, peer_client_public_key)

    # Both client and server should derive the same shared key
    assert shared_key_client == shared_key_server, "Shared keys do not match!"

    # Server => Client: HAMK
    print("Verifying session on client...")
    usr.verify_session(HAMK)
    print("Session verified on client.")

    # At this point the authentication process is complete.
    print("Authentication process completed.")
    assert usr.authenticated()
    assert svr.authenticated()
    print("Both user and server are authenticated.")

# Lancer le processus d'authentification
authentication_process()
