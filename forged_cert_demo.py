"""
@brief Live demo: certificate forgery detection with real TTP + Server.

Demonstrates two authentication scenarios using the actual live system:
  1. CORRECT: Legitimate User (TTP-signed cert) → authentication succeeds
  2. INCORRECT: Attacker sends a forged self-signed cert → authentication REJECTED

This proves MITM resistance: an interceptor cannot impersonate
a user because they lack the TTP's private signing key.

Usage:
    1. Terminal 1:  python3 ttp.py
    2. Terminal 2:  python3 server.py
    3. Terminal 3:  python3 forged_cert_demo.py
"""

import socket
import threading
import time
import sys

from common import *


def print_separator(char="="):
    print()
    print(char * 60)


def recv_msg_timeout(sock, timeout=15):
    """Receive one message with a timeout."""
    sock.settimeout(timeout)
    try:
        return recv_msg(sock)
    except socket.timeout:
        return None
    finally:
        sock.settimeout(None)


# ─── Helper: complete a registration with TTP and return (sock, cert_pem) ───

def register_with_ttp(host, port, role, display_id, keypair):
    """
    Register an entity with the TTP.
    Returns (sock, cert_pem, ttp_pubkey) or raises on failure.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))

    # 1. Receive TTP public key
    msg = recv_msg_timeout(sock)
    if not msg or msg.get("type") != MSG_TTP_PUBLIC_KEY:
        raise RuntimeError("Expected TTP_PUBLIC_KEY")
    ttp_pubkey = deserialize_public_key(msg["public_key"])

    # 2. Send registration
    id_hash = hash_id(display_id)
    pub_pem = serialize_public_key(keypair.public_key())
    payload = json.dumps({
        "id_hash": id_hash,
        "public_key": pub_pem,
        "display_id": display_id,
    }).encode("utf-8")
    ekey, nonce, ct = hybrid_encrypt(ttp_pubkey, payload)
    send_msg(sock, {
        "type": MSG_REGISTER,
        "role": role,
        "encrypted_key": ekey.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ct.hex(),
    })

    # 3. Receive certificate
    msg = recv_msg_timeout(sock)
    if not msg or msg.get("type") != MSG_CERTIFICATE:
        raise RuntimeError("Expected CERTIFICATE")
    return sock, msg["certificate"], ttp_pubkey


def request_service(server_host, server_port, user_id_hash):
    """Connect to server and send a service request. Returns the socket."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((server_host, server_port))
    send_msg(sock, {
        "type": MSG_SERVICE_REQUEST,
        "user_id_hash": user_id_hash,
        "service_type": "encrypted_echo",
    })
    return sock


def wait_for_session_key(sock, keypair, timeout=35):
    """Wait on the TTP persistent connection for AUTH_OK with a session key."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        msg = recv_msg_timeout(sock, min(remaining, 5))
        if msg is None:
            break
        if msg.get("type") == MSG_AUTH_OK:
            sk_enc = msg.get("session_key_encrypted")
            if sk_enc:
                return rsa_decrypt(keypair, bytes.fromhex(sk_enc))
        # Ignore intermediate AUTH_OK without session key
    return None


def main():
    ttp_host = TTP_HOST
    ttp_port = TTP_PORT
    srv_host = SERVER_HOST
    srv_port = SERVER_PORT

    print("BSK Project — Certificate Forgery & MITM Resistance Demo")
    print("=" * 60)
    print(f"TTP:    {ttp_host}:{ttp_port}")
    print(f"Server: {srv_host}:{srv_port}")
    print()
    print("(Running — make sure TTP and Server are up)")

    # ─────────────────────────────────────────────────────────
    # SCENARIO A: Legitimate user → authentication succeeds
    # ─────────────────────────────────────────────────────────
    print_separator()
    print("  SCENARIO A: Legitimate User (TTP-signed cert)")
    print("  Expect: authentication succeeds, session key received")
    print_separator()

    try:
        # Generate keypair and register with TTP
        legit_key = generate_rsa_keypair()
        ttp_sock, cert_pem, ttp_pubkey = register_with_ttp(
            ttp_host, ttp_port, "user", "Legitimate-User", legit_key
        )
        legit_id_hash = hash_id("Legitimate-User")
        print("  [+] Registered with TTP, obtained X.509 certificate")
        print(f"  [+] ID hash: {legit_id_hash[:16]}...")

        # Request service from Server
        srv_sock = request_service(srv_host, srv_port, legit_id_hash)
        print("  [+] Service request sent to Server")
        print("  [i] Server will now authenticate with TTP...")

        # Listen for AUTH_USER_START on the TTP connection
        print("  [i] Waiting for TTP's authentication challenge...")
        msg = recv_msg_timeout(ttp_sock, 15)
        if msg and msg.get("type") == MSG_AUTH_USER_START:
            print("  [+] Received AUTH_USER_START from TTP")

            # Respond with our REAL certificate (TTP-signed)
            payload = json.dumps({
                "id_hash": legit_id_hash,
                "certificate": cert_pem,
            }).encode("utf-8")
            ekey, nonce, ct = hybrid_encrypt(ttp_pubkey, payload)
            send_msg(ttp_sock, {
                "type": MSG_AUTH_USER_RESPONSE,
                "encrypted_key": ekey.hex(),
                "nonce": nonce.hex(),
                "ciphertext": ct.hex(),
            })
            print("  [+] Authentication response sent (with real cert)")

            # Wait for the session key
            session_key = wait_for_session_key(ttp_sock, legit_key)
            if session_key:
                print("  [+] SESSION KEY RECEIVED — authentication SUCCEEDED!")
                print("  [!] VERDICT: Legitimate user → CORRECTLY AUTHENTICATED")
            else:
                print("  [!] No session key received — check TTP/Server logs")
        else:
            print(f"  [!] Unexpected message: {msg}")

        # Clean up scenario A connections
        ttp_sock.close()
        srv_sock.close()
        time.sleep(1)  # Let connections settle

    except Exception as e:
        print(f"  [!!] Scenario A failed: {e}")

    # ─────────────────────────────────────────────────────────
    # SCENARIO B: Attacker with forged self-signed cert → rejected
    # ─────────────────────────────────────────────────────────
    print_separator()
    print("  SCENARIO B: Attacker (forged SELF-SIGNED certificate)")
    print("  Expect: TTP REJECTS authentication, NO session key")
    print_separator()

    try:
        # Attacker generates their OWN keypair (not controlled by TTP)
        attacker_key = generate_rsa_keypair()

        # The attacker CANNOT get their forged cert from TTP (TTP signs everything),
        # so they self-sign it — like creating their own fake CA
        attacker_fake_ca_key = generate_rsa_keypair()
        attacker_fake_ca_cert = create_self_signed_cert(attacker_fake_ca_key, "Fake-CA")
        forged_cert = create_signed_cert(
            attacker_key.public_key(),
            attacker_fake_ca_key,    # Signed by attacker's fake CA, NOT by real TTP!
            attacker_fake_ca_cert.subject,
            "server_Legitimate-Server-01",  # Impersonating the real server
        )
        forged_cert_pem = serialize_cert(forged_cert)
        attacker_id_hash = hash_id("Attacker-User")
        print("  [!!] Attacker generates their OWN RSA keypair")
        print("  [!!] Attacker creates self-signed 'Fake-CA'")

        # Attacker still needs to connect to TTP and register
        # (to get on the network and receive TTP's public key for encryption)
        # But they register with THEIR OWN identity, not the forged one
        # They can't register with a forged ID because TTP issues its own cert anyway
        ttp_sock2, _, ttp_pubkey2 = register_with_ttp(
            ttp_host, ttp_port, "user", "Attacker-User", attacker_key
        )
        print("  [!!] Attacker registers with TTP (gets real cert for 'Attacker-User')")
        print("  [!!] BUT during auth, attacker sends a FORGED self-signed cert!")

        # Request service from Server
        srv_sock2 = request_service(srv_host, srv_port, attacker_id_hash)
        print("  [!!] Service request sent (impersonating a different user)")

        # Wait for AUTH_USER_START
        print("  [i] Waiting for TTP's authentication challenge...")
        msg = recv_msg_timeout(ttp_sock2, 15)
        if msg and msg.get("type") == MSG_AUTH_USER_START:
            print("  [!!] Received AUTH_USER_START — attacker responds with FORGED cert")

            # 🔥 Attacker sends a FORGED certificate (self-signed, not by TTP)
            payload = json.dumps({
                "id_hash": attacker_id_hash,
                "certificate": forged_cert_pem,  # <-- FORGED, not the real TTP cert!
            }).encode("utf-8")
            ekey, nonce, ct = hybrid_encrypt(ttp_pubkey2, payload)
            send_msg(ttp_sock2, {
                "type": MSG_AUTH_USER_RESPONSE,
                "encrypted_key": ekey.hex(),
                "nonce": nonce.hex(),
                "ciphertext": ct.hex(),
            })
            print("  [!!] Forged certificate sent to TTP")

            # Wait for session key — should NOT arrive
            session_key = wait_for_session_key(ttp_sock2, attacker_key, timeout=10)
            if session_key:
                print("  [!!] SESSION KEY RECEIVED — authentication SUCCEEDED!")
                print("  [!!] VULNERABILITY: forged cert was ACCEPTED!")
            else:
                print("  [!] No session key received (expected)")
                print("  [+] TTP REJECTED the forged certificate!")
                print("  [+] VERDICT: Attacker with forged cert → CORRECTLY DENIED")

                # Check for ERROR message from TTP
                ttp_sock2.settimeout(2)
                try:
                    err = recv_msg(ttp_sock2)
                    if err and err.get("type") == MSG_ERROR:
                        print(f'  [+] TTP error message: "{err.get("message")}"')
                except (socket.timeout, OSError):
                    pass
                ttp_sock2.settimeout(None)
        else:
            print(f"  [!] Unexpected message: {msg}")

        ttp_sock2.close()
        srv_sock2.close()

    except Exception as e:
        print(f"  [!!] Scenario B failed: {e}")

    # ─────────────────────────────────────────────────────────
    # SUMMARY
    # ─────────────────────────────────────────────────────────
    print_separator()
    print("  SUMMARY")
    print_separator()
    print("""
  Scenario A (Legitimate User):
    TTP-signed cert  →  SIGNATURE VALID   →  SESSION KEY DELIVERED  →  AUTH OK

  Scenario B (Attacker with forged cert):
    Self-signed cert  →  NOT signed by TTP →  SIGNATURE INVALID     →  AUTH DENIED

  MITM resistance:
    An interceptor cannot forge a valid certificate because they
    do not possess the TTP's private signing key. Any certificate
    not carrying a valid TTP signature is rejected during
    authentication — the attack is detected and blocked.
    """)
    print("=" * 60)
    print("Demo complete.")
    print("=" * 60)


if __name__ == "__main__":
    main()
