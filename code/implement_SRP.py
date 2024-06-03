import srp


if __name__ == '__main__':
    # The salt and verifier returned from srp.create_salted_verification_key() should be
    # stored on the server.
    print("Creating salted verification key...")
    salt, vkey = srp.create_salted_verification_key('testuser', 'testpassword')
    print("Salt and verification key created.")

    class AuthenticationFailed(Exception):
        pass

    # ~~~ Begin Authentication ~~~

    print("Starting user authentication...")
    usr = srp.User('testuser', 'testpassword')
    uname, A = usr.start_authentication()
    print(f"User authentication started. Username: {uname}, A: {A}")

    # The authentication process can fail at each step from this
    # point on. To comply with the SRP protocol, the authentication
    # process should be aborted on the first failure.

    # Client => Server: username, A
    print("Creating server verifier...")
    svr = srp.Verifier(uname, salt, vkey, A)
    s, B = svr.get_challenge()
    print(f"Server verifier created. Salt: {s}, B: {B}")

    if s is None or B is None:
        raise AuthenticationFailed()

    # Server => Client: s, B
    print("Processing server challenge...")
    M = usr.process_challenge(s, B)
    print(f"Challenge processed. M: {M}")

    if M is None:
        raise AuthenticationFailed()

    # Client => Server: M
    print("Verifying session on server...")
    HAMK = svr.verify_session(M)
    print(f"Session verified on server. HAMK: {HAMK}")

    if HAMK is None:
        raise AuthenticationFailed()

    # Server => Client: HAMK
    print("Verifying session on client...")
    usr.verify_session(HAMK)
    print("Session verified on client.")

    # At this point the authentication process is complete.
    print("Authentication process completed.")
    assert usr.authenticated()
    assert svr.authenticated()
    print("Both user and server are authenticated.")


