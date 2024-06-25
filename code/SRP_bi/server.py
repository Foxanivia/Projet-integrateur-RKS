import srp
import socket
import json
import base64

class AuthenticationFailed(Exception):
    """Exception levée en cas d'échec de l'authentification."""
    pass

def create_salted_verification_key(username, password):
    """Crée une clé de vérification salée pour un utilisateur donné."""
    print("Creating salted verification key...")
    salt, vkey = srp.create_salted_verification_key(username, password)
    salt_encoded = base64.b64encode(salt).decode('utf-8')
    print("Salt and verification key created.\n")
    return salt_encoded, vkey

def create_server_verifier(username, salt_encoded, vkey, A_encoded):
    """Crée un vérificateur de serveur pour l'utilisateur."""
    salt = base64.b64decode(salt_encoded)
    A = base64.b64decode(A_encoded)
    print("Creating server verifier...")
    svr = srp.Verifier(username, salt, vkey, A)
    s, B = svr.get_challenge()
    s_encoded = base64.b64encode(s).decode('utf-8')
    B_encoded = base64.b64encode(B).decode('utf-8')
    print(f"Server verifier created. Salt: {s_encoded}, B: {B_encoded}\n")
    return svr, s_encoded, B_encoded

def verify_session_on_server(svr, M_encoded):
    """Vérifie la session sur le serveur."""
    M = base64.b64decode(M_encoded)
    print("Verifying session on server...")
    HAMK = svr.verify_session(M)
    HAMK_encoded = base64.b64encode(HAMK).decode('utf-8')
    print(f"Session verified on server. HAMK: {HAMK_encoded}\n")
    return HAMK_encoded

def send_to_client(data, conn):
    """Envoie les données au client."""
    conn.sendall(json.dumps(data).encode('utf-8'))

def receive_from_client(conn):
    """Reçoit les données du client."""
    data = conn.recv(1024)
    return json.loads(data.decode('utf-8'))

def main():
    # Informations utilisateur pour l'exemple (côté serveur, ces infos devraient être dans une base de données)
    username = 'testuser'
    password = 'testpassword'

    # Création de la clé de vérification avec salage (simulée ici)
    salt_encoded, vkey = create_salted_verification_key(username, password)

    # Création du socket serveur
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('0.0.0.0', 8080))
        s.listen()
        print("Server is listening on port 8080...")
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")

            # Réception des données de l'utilisateur
            client_data = receive_from_client(conn)
            uname = client_data['username']
            A_encoded = client_data['A']

            # Création du vérificateur du serveur
            svr, s_encoded, B_encoded = create_server_verifier(uname, salt_encoded, vkey, A_encoded)

            # Si le serveur échoue à créer le challenge, l'authentification échoue
            if s_encoded is None or B_encoded is None:
                raise AuthenticationFailed()

            print("ENVOI DE S ET B")
            # Envoi du défi au client
            send_to_client({'s': s_encoded, 'B': B_encoded}, conn)

            # Réception de M du client pour vérification de la session
            client_data = receive_from_client(conn)
            M_encoded = client_data['M']

            # Si le serveur échoue à vérifier la session, l'authentification échoue
            if M_encoded is None:
                raise AuthenticationFailed()

            # Vérification de la session sur le serveur
            HAMK_encoded = verify_session_on_server(svr, M_encoded)

            # Envoi de la vérification finale au client
            send_to_client({'HAMK': HAMK_encoded}, conn)

            # Vérification que le serveur est authentifié
            print("Authentication process completed.")
            if svr.authenticated():
                print("Server is authenticated.")
            else:
                raise AuthenticationFailed()

if __name__ == '__main__':
    main()
