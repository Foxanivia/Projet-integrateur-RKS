# Importation de la bibliothèque SRP
import srp


class AuthenticationFailed(Exception):
    """Exception levée en cas d'échec de l'authentification."""
    pass


def create_salted_verification_key(username, password):
    """
    Crée une clé de vérification salée pour un utilisateur donné.
    La clé de vérification salée doit être stockée sur le serveur.
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
    HAMK = svr.verify_session(M)
    print(f"Session verified on server. HAMK: {HAMK}\n")
    return HAMK


def verify_session_on_client(usr, hamk):
    """
    Vérifie la session sur le client.
    """
    print("Verifying session on client...")
    usr.verify_session(hamk)
    print("Session verified on client.\n")


def main():
    # Informations utilisateur pour l'exemple
    username = 'testuser'
    password = 'testpassword'

    # Création de la clé de vérification avec salage (sur serveur)
    salt, vkey = create_salted_verification_key(username, password)

    # Début de l'authentification utilisateur
    usr, uname, A = start_user_authentication(username, password)

    # Envoi du nom d'utilisateur et de A au serveur et création du vérificateur du serveur
    svr, s, B = create_server_verifier(uname, salt, vkey, A)

    # Si le serveur échoue à créer le challenge, l'authentification échoue
    if s is None or B is None:
        raise AuthenticationFailed()

    # Le client traite le challenge du serveur
    M = process_server_challenge(usr, s, B)

    # Si le client échoue à traiter le challenge, l'authentification échoue
    if M is None:
        raise AuthenticationFailed()

    # Le client envoie M au serveur pour vérification de la session
    HAMK = verify_session_on_server(svr, M)

    # Si le serveur échoue à vérifier la session, l'authentification échoue
    if HAMK is None:
        raise AuthenticationFailed()

    # Le serveur envoie HAMK au client pour vérification finale de la session
    verify_session_on_client(usr, HAMK)

    # Vérification que les deux parties sont authentifiées
    print("Authentication process completed.")
    assert usr.authenticated()
    assert svr.authenticated()
    print("Both user and server are authenticated.")


if __name__ == '__main__':
    main()
