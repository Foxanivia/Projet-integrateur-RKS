import srp
import socket
import json
import base64

class AuthenticationFailed(Exception):
    """Exception levée en cas d'échec de l'authentification."""
    pass

def start_user_authentication(username, password):
    """Démarre le processus d'authentification pour l'utilisateur."""
    print("Starting user authentication...")
    usr = srp.User(username, password)
    uname, A = usr.start_authentication()
    A_encoded = base64.b64encode(A).decode('utf-8')
    print(f"User authentication started. Username: {uname}, A: {A_encoded}\n")
    return usr, uname, A_encoded

def process_server_challenge(usr, s_encoded, B_encoded):
    """Traite le défi envoyé par le serveur."""
    s = base64.b64decode(s_encoded)
    B = base64.b64decode(B_encoded)
    print("Processing server challenge...")
    M = usr.process_challenge(s, B)
    M_encoded = base64.b64encode(M).decode('utf-8')
    print(f"Challenge processed. M: {M_encoded}\n")
    return M_encoded

def verify_session_on_client(usr, hamk_encoded):
    """Vérifie la session sur le client."""
    hamk = base64.b64decode(hamk_encoded)
    print("Verifying session on client...")
    usr.verify_session(hamk)
    print("Session verified on client.\n")

def send_to_server(conn, data):
    """Envoie les données au serveur."""
    conn.sendall(json.dumps(data).encode('utf-8'))

def receive_from_server(conn):
    """Reçoit les données du serveur."""
    data = conn.recv(1024)
    return json.loads(data.decode('utf-8'))

def main():
    # Informations utilisateur pour l'exemple
    username = 'testuser'
    password = 'testpassword'

    # Début de l'authentification utilisateur
    usr, uname, A_encoded = start_user_authentication(username, password)

    # Initialisation de la connexion au serveur
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect(('localhost', 8080))

    try:
        # Envoi du nom d'utilisateur et de A au serveur
        send_to_server(conn, {'username': uname, 'A': A_encoded})

        # Réception du défi du serveur
        server_data = receive_from_server(conn)
        s_encoded = server_data['s']
        B_encoded = server_data['B']

        # Si le serveur échoue à créer le challenge, l'authentification échoue
        if s_encoded is None or B_encoded is None:
            raise AuthenticationFailed()

        # Le client traite le challenge du serveur
        M_encoded = process_server_challenge(usr, s_encoded, B_encoded)

        # Si le client échoue à traiter le challenge, l'authentification échoue
        if M_encoded is None:
            raise AuthenticationFailed()

        # Envoi de M au serveur pour vérification de la session
        send_to_server(conn, {'M': M_encoded})

        # Réception de la vérification finale du serveur
        server_data = receive_from_server(conn)
        HAMK_encoded = server_data['HAMK']

        # Si le serveur échoue à vérifier la session, l'authentification échoue
        if HAMK_encoded is None:
            raise AuthenticationFailed()

        # Vérification finale de la session sur le client
        verify_session_on_client(usr, HAMK_encoded)

        # Vérification que le client est authentifié
        print("Authentication process completed.")
        if usr.authenticated():
            print("Client is authenticated.")
        else:
            raise AuthenticationFailed()
    finally:
        conn.close()

if __name__ == '__main__':
    main()
