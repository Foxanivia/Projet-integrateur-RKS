# Bibliothèque
import srp
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import time
import psutil


########################################
#         Monitoring et Erreur         #
########################################
class AuthenticationFailed(Exception):
    """Exception levée en cas d'échec de l'authentification."""
    pass


def measure_performance(func):
    """
    Mesure la performance en termes de temps et de consommation énergétique.
    @param func: La fonction à mesurer.
    @return: Le résultat de la fonction exécutée.
    """
    def wrapper(*args, **kwargs):
        start_time = time.time()
        start_energy = psutil.sensors_battery().percent if psutil.sensors_battery() else None
        result = func(*args, **kwargs)
        end_time = time.time()
        end_energy = psutil.sensors_battery().percent if psutil.sensors_battery() else None
        print(f"Time taken by {func.__name__}: {end_time - start_time} seconds")
        if start_energy is not None and end_energy is not None:
            print(f"Energy consumed by {func.__name__}: {start_energy - end_energy} %")
        return result
    return wrapper

########################################
#                ECDHE                 #
########################################

def generate_key_pair():
    """
    Génère une paire de clés (priv/pub) ECDHE.
    @return: Tuple contenant la clé privée et la clé publique.
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key(public_key):
    """
    Sérialise une clé pub en format PEM.
    @param public_key: La clé pub à sérialiser.
    @return: La clé publ en format PEM.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def deserialize_public_key(pem_data):
    """
    Désérialise une clé pub à partir du format PEM.
    @param pem_data: Les données PEM de la clé pub.
    @return: La clé pub désérialisée.
    """
    return serialization.load_pem_public_key(pem_data)


def derive_shared_key(private_key, peer_public_key):
    """
    Dérive une clé partagée à partir d'une clé priv et d'une clé pub.
    @param private_key: La clé privée.
    @param peer_public_key: La clé publique.
    @return: La clé dérivée partagée.
    """
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data'
    ).derive(shared_key)


########################################
#                SRP                   #
########################################
def create_salted_verification_key(username, password):
    """
    Crée une clé de vérification + salage pour un utilisateur.
    La clé de vérification + salage et stocké sur le serv.
    """
    print("Creating salted verification key...")
    salt, vkey = srp.create_salted_verification_key(username, password)
    print("Salt and verification key created.\n")
    return salt, vkey


def start_user_authentication(username, password):
    """
    Démarre le processus d'authentification pour l'utilisateur.
    """
    print("Starting user authentication...")
    usr = srp.User(username, password)
    uname, A = usr.start_authentication()
    print(f"User authentication started. Username: {uname}, A: {A}\n")
    return usr, uname, A


def create_server_verifier(username, salt, vkey, A):
    """
    Crée un vérificateur de serveur pour l'utilisateur.
    """
    print("Creating server verifier...")
    svr = srp.Verifier(username, salt, vkey, A)
    s, B = svr.get_challenge()
    print(f"Server verifier created. Salt: {s}, B: {B}\n")
    return svr, s, B


def process_server_challenge(usr, s, B):
    """
    Traite le défi envoyé par le serveur.
    """
    print("Processing server challenge...")
    M = usr.process_challenge(s, B)
    print(f"Challenge processed. M: {M}\n")
    return M


def verify_session_on_server(svr, M):
    """
    Vérifie la session sur le serveur.
    """
    print("Verifying session on server...")
    hamk = svr.verify_session(M)
    print(f"Session verified on server. HAMK: {hamk}\n")
    return hamk


def verify_session_on_client(usr, hamk):
    """
    Vérifie la session sur le client.
    """
    print("Verifying session on client...")
    usr.verify_session(hamk)
    print("Session verified on client.\n")


@measure_performance
def authentication_process():
    """
    Implémentation complète de SRP avec ECDHE.
    """
    # Initialisation de la clé de vérification salée
    username = 'testuser'
    password = 'testpassword'
    salt, vkey = create_salted_verification_key(username, password)

    # Démarrage de l'authentification utilisateur
    usr, uname, A = start_user_authentication(username, password)

    # Création du vérificateur du serveur
    svr, s, B = create_server_verifier(uname, salt, vkey, A)

    if s is None or B is None:
        raise AuthenticationFailed()

    # Génération des clés ECDHE côté client
    client_private_key, client_public_key = generate_key_pair()
    serialized_client_public_key = serialize_public_key(client_public_key)

    # Traitement du défi serveur par le client
    M = process_server_challenge(usr, s, B)

    if M is None:
        raise AuthenticationFailed()

    # Génération des clés ECDHE côté serveur
    server_private_key, server_public_key = generate_key_pair()
    serialized_server_public_key = serialize_public_key(server_public_key)

    # Désérialisation et dérivation de la clé partagée côté client
    peer_server_public_key = deserialize_public_key(serialized_server_public_key)
    shared_key_client = derive_shared_key(client_private_key, peer_server_public_key)

    # Vérification de la session côté serveur
    HAMK = verify_session_on_server(svr, M)

    if HAMK is None:
        raise AuthenticationFailed()

    # Désérialisation et dérivation de la clé partagée côté serveur
    peer_client_public_key = deserialize_public_key(serialized_client_public_key)
    shared_key_server = derive_shared_key(server_private_key, peer_client_public_key)

    # Vérification que les clés partagées sont identiques
    assert shared_key_client == shared_key_server, "Shared keys do not match!"

    # Vérification de la session côté client
    verify_session_on_client(usr, HAMK)

    # Vérification finale que les deux parties sont authentifiées
    print("Authentication process completed.")
    assert usr.authenticated()
    assert svr.authenticated()
    print("Both user and server are authenticated.")


if __name__ == '__main__':
    # Lancer le processus d'authentification
    authentication_process()
