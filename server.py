"""
@brief Service Server implementation for the BSK project.

The Server provides an encrypted echo service to authenticated Users.
It registers with the TTP on startup, obtains an X.509 certificate,
listens for client connections, and facilitates mutual authentication
via the TTP before allowing encrypted communication.

Usage:
    python3 server.py
"""

import threading
import logging
import socket
import sys

from common import *


class Server:
    """
    @brief Service server that registers with TTP and provides encrypted services.

    The Server maintains a persistent connection to TTP for certificate
    management and creates separate authentication connections when
    a client requests service. It handles the full authentication flow
    and provides an encrypted echo service.
    """

    def __init__(self, ttp_host=TTP_HOST, ttp_port=TTP_PORT,
                 server_host=SERVER_HOST, server_port=SERVER_PORT,
                 server_id="Server-01"):
        """
        @brief Initialize the Server.

        Generates the Server's RSA 4096 key pair and sets up logging to
        both file (server.log) and console. Initializes session state.

        @param ttp_host     TTP server host address.
        @param ttp_port     TTP server TCP port.
        @param server_host  Address for the Server to listen on.
        @param server_port  Port for the Server to listen on.
        @param server_id    Human-readable identifier for this server.
        """
        self.server_id = server_id
        self.ttp_host = ttp_host
        self.ttp_port = ttp_port
        self.server_host = server_host
        self.server_port = server_port
        self.logger = self._setup_logging()

        self.server_key = generate_rsa_keypair()
        self.server_cert_pem = None
        self.server_id_hash = None

        self.session_key = None
        self.session_event = threading.Event()
        self.session_client = None
        self.lock = threading.Lock()

    def _setup_logging(self):
        """
        @brief Configure logging with timestamps to server.log and stdout.

        @return  A configured logging.Logger instance.
        """
        logger = logging.getLogger("Server")
        logger.setLevel(logging.INFO)
        fh = logging.FileHandler("server.log")
        fh.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        )
        logger.addHandler(fh)
        sh = logging.StreamHandler()
        sh.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        )
        logger.addHandler(sh)
        return logger

    def start(self):
        """
        @brief Start the Server.

        Performs two main steps:
        1. Registers with the TTP (obtains X.509 certificate)
        2. Listens for client TCP connections in an infinite loop

        Each client connection is handled in a separate daemon thread.
        """
        # 1. Register with TTP
        self._register_with_ttp()

        # 2. Listen for client connections
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((self.server_host, self.server_port))
        server_sock.listen(5)
        self.logger.info("Listening on %s:%d", self.server_host, self.server_port)
        print(f"Server listening on {self.server_host}:{self.server_port}")
        print("Waiting for client connection...\n")

        try:
            while True:
                client_sock, addr = server_sock.accept()
                self.logger.info("Client connected from %s:%d", *addr)
                print(f"\n[+] Client connected from {addr[0]}:{addr[1]}")
                t = threading.Thread(
                    target=self._handle_client, args=(client_sock, addr),
                    daemon=True,
                )
                t.start()
        except KeyboardInterrupt:
            print("\nServer shutting down.")
            self.logger.info("Server shut down")

    def _register_with_ttp(self):
        """
        @brief Connect to TTP and register the Server.

        Protocol sequence:
        1. Connect to TTP and receive TTP's public key
        2. Send registration payload (id_hash + public key) encrypted with
           hybrid RSA-AES encryption
        3. Receive signed X.509 certificate from TTP
        4. Start a listener thread on the persistent TTP connection

        Exits the process on failure.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.ttp_host, self.ttp_port))
        self.logger.info("Connected to TTP at %s:%d", self.ttp_host, self.ttp_port)
        print(f"Connected to TTP at {self.ttp_host}:{self.ttp_port}")

        # Receive TTP public key
        msg = recv_msg(sock)
        if not msg or msg.get("type") != MSG_TTP_PUBLIC_KEY:
            self.logger.error("Expected TTP_PUBLIC_KEY from TTP")
            sys.exit(1)

        ttp_public_key_pem = msg["public_key"]
        ttp_public_key = deserialize_public_key(ttp_public_key_pem)
        self.logger.info("Received TTP public key")

        # Send registration
        id_hash = hash_id(self.server_id)
        self.server_id_hash = id_hash
        public_key_pem = serialize_public_key(self.server_key.public_key())

        payload = json.dumps({
            "id_hash": id_hash,
            "public_key": public_key_pem,
            "display_id": self.server_id,
        }).encode("utf-8")
        encrypted_key, nonce, ciphertext = hybrid_encrypt(ttp_public_key, payload)

        send_msg(sock, {
            "type": MSG_REGISTER,
            "role": "server",
            "encrypted_key": encrypted_key.hex(),
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
        })
        self.logger.info("Sent registration to TTP")

        # Receive certificate
        msg = recv_msg(sock)
        if not msg or msg.get("type") != MSG_CERTIFICATE:
            self.logger.error("Expected CERTIFICATE from TTP")
            sys.exit(1)

        self.server_cert_pem = msg["certificate"]
        self.logger.info("Received X.509 certificate from TTP")
        print(f"  [+] Server registered with TTP — certificate obtained")
        print(f"  [+] Server ID hash: {id_hash[:16]}...")

        # Start TTP listener thread (handles incoming AUTH_OK messages
        # on the persistent connection)
        t = threading.Thread(
            target=self._ttp_listener, args=(sock,), daemon=True
        )
        t.start()

    def _ttp_listener(self, sock):
        """
        @brief Listen for messages from TTP on the persistent connection.

        Handles AUTH_OK messages (which deliver the session key) and
        ERROR messages from the TTP.

        @param sock  The persistent TTP connection socket.
        """
        try:
            while True:
                msg = recv_msg(sock)
                if msg is None:
                    self.logger.warning("TTP connection lost")
                    print("\n[!] TTP connection lost")
                    break

                msg_type = msg.get("type")
                if msg_type == MSG_AUTH_OK:
                    for_field = msg.get("for")
                    sk_enc_hex = msg.get("session_key_encrypted")
                    if sk_enc_hex:
                        encrypted_sk = bytes.fromhex(sk_enc_hex)
                        session_key = rsa_decrypt(self.server_key, encrypted_sk)
                        with self.lock:
                            self.session_key = session_key
                        self.session_event.set()
                        self.logger.info(
                            "Received session key from TTP"
                        )
                        print(
                            "\n  [+] Server: session key received from TTP"
                        )
                    if msg.get("message"):
                        self.logger.info("TTP: %s", msg["message"])
                        print(f"  [i] TTP message: {msg['message']}")
                elif msg_type == MSG_ERROR:
                    self.logger.error("TTP error: %s", msg.get("message"))
                    print(f"\n  [!] TTP error: {msg.get('message')}")
                else:
                    self.logger.debug("Unhandled TTP msg: %s", msg_type)
        except Exception as e:
            self.logger.error("TTP listener error: %s", e)

    def _handle_client(self, client_sock, addr):
        """
        @brief Handle a client connection: service request, auth, encrypted loop.

        @param client_sock  The client's TCP socket.
        @param addr         The client's (host, port) address tuple.
        """
        try:
            # Receive service request
            msg = recv_msg(client_sock)
            if not msg:
                return

            if msg.get("type") == MSG_SERVICE_REQUEST:
                user_id_hash = msg.get("user_id_hash")
                service_type = msg.get("service_type", "unknown")
                self.logger.info(
                    "Service request from user %s (type: %s)",
                    user_id_hash[:16], service_type,
                )
                print(
                    f"  [i] Service request from user {user_id_hash[:16]}..."
                    f" (type: {service_type})"
                )

                # Initiate authentication with TTP
                self._initiate_auth(user_id_hash)

                print(f"  [i] Waiting for session key from TTP...")

                # Wait for session key
                if not self.session_event.wait(timeout=30):
                    self.logger.error("Session key timeout")
                    send_msg(client_sock, {
                        "type": MSG_ERROR,
                        "message": "Authentication timeout",
                    })
                    return

                with self.lock:
                    sk = self.session_key

                self.logger.info("Authentication complete — session active")
                print(f"\n  [+] Authentication complete — encrypted session active")
                print(f"  [i] You can now exchange encrypted messages with the client.")

                self.session_client = client_sock

                # Enter encrypted communication loop
                self._encrypted_loop(client_sock, sk)
            else:
                send_msg(client_sock, {
                    "type": MSG_ERROR,
                    "message": "Expected SERVICE_REQUEST",
                })
        except Exception as e:
            self.logger.error("Client handler error: %s", e)
        finally:
            try:
                client_sock.close()
            except Exception:
                pass
            self.session_event.clear()
            with self.lock:
                self.session_key = None

    def _initiate_auth(self, user_id_hash):
        """
        @brief Initiate the authentication process with TTP.

        Opens a new TCP connection to TTP, registers (using a separate
        auth-specific ID hash), sends an AUTH_SERVER request, and waits
        for the session key in the AUTH_OK response.

        @param user_id_hash  SHA-256 hash of the requesting User's ID.
        """
        auth_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        auth_sock.connect((self.ttp_host, self.ttp_port))
        # Receive TTP public key
        msg = recv_msg(auth_sock)
        if not msg or msg.get("type") != MSG_TTP_PUBLIC_KEY:
            self.logger.error("Expected TTP_PUBLIC_KEY")
            auth_sock.close()
            return
        # Re-register quickly
        id_hash = hash_id(self.server_id + "_auth")
        public_key_pem = serialize_public_key(self.server_key.public_key())
        payload = json.dumps({
            "id_hash": id_hash,
            "public_key": public_key_pem,
            "display_id": self.server_id,
        }).encode("utf-8")
        ttp_pubkey = deserialize_public_key(msg["public_key"])
        encrypted_key, nonce, ciphertext = hybrid_encrypt(ttp_pubkey, payload)
        send_msg(auth_sock, {
            "type": MSG_REGISTER,
            "role": "server",
            "encrypted_key": encrypted_key.hex(),
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
        })
        msg2 = recv_msg(auth_sock)
        if not msg2 or msg2.get("type") != MSG_CERTIFICATE:
            auth_sock.close()
            return

        # Now send AUTH_SERVER
        send_msg(auth_sock, {
            "type": MSG_AUTH_SERVER,
            "user_id_hash": user_id_hash,
        })
        self.logger.info("Sent AUTH_SERVER to TTP for user %s", user_id_hash[:16])
        print(f"  [i] Server → TTP: authenticate user {user_id_hash[:16]}...")

        # Wait for AUTH_OK
        while True:
            resp = recv_msg(auth_sock)
            if resp is None:
                break
            if resp.get("type") == MSG_AUTH_OK:
                sk_enc_hex = resp.get("session_key_encrypted")
                if sk_enc_hex:
                    encrypted_sk = bytes.fromhex(sk_enc_hex)
                    session_key = rsa_decrypt(self.server_key, encrypted_sk)
                    with self.lock:
                        self.session_key = session_key
                    self.session_event.set()
                    self.logger.info("Received session key from TTP (auth conn)")
                    print("\n  [+] Server: session key received")
                break
            elif resp.get("type") == MSG_ERROR:
                self.logger.error("Auth error: %s", resp.get("message"))
                print(f"\n  [!] Auth error: {resp.get('message')}")
                break

        auth_sock.close()

    def _encrypted_loop(self, client_sock, session_key):
        """
        @brief Handle AES-256-GCM encrypted communication with a client.

        Receives ENCRYPTED_DATA messages, decrypts them, prints the plaintext,
        and echoes back a "Server echo: ..." response (also encrypted).

        @param client_sock  The client's TCP socket.
        @param session_key  The AES-256 session key (32 bytes).
        """
        print("\n" + "=" * 50)
        print("  ENCRYPTED SESSION ACTIVE")
        print("=" * 50)

        while True:
            msg = recv_msg(client_sock)
            if msg is None:
                self.logger.info("Client disconnected")
                print("\n[!] Client disconnected")
                break

            if msg.get("type") == MSG_ENCRYPTED_DATA:
                nonce = bytes.fromhex(msg["nonce"])
                ciphertext = bytes.fromhex(msg["ciphertext"])
                try:
                    plaintext = aes_decrypt(session_key, nonce, ciphertext)
                    decoded = plaintext.decode("utf-8")
                    self.logger.info("Received (encrypted): %s", decoded)
                    print(f"\n  [IN] (encrypted) << {decoded}")

                    # Echo back
                    response = f"Server echo: {decoded}".encode("utf-8")
                    resp_nonce, resp_ct = aes_encrypt(session_key, response)
                    send_msg(client_sock, {
                        "type": MSG_ENCRYPTED_DATA,
                        "nonce": resp_nonce.hex(),
                        "ciphertext": resp_ct.hex(),
                    })
                    self.logger.info("Sent response: Server echo: %s", decoded)
                    print(f"  [OUT] (encrypted) >> Server echo: {decoded}")
                except Exception as e:
                    self.logger.error("Decryption failed: %s", e)
                    send_msg(client_sock, {
                        "type": MSG_ERROR,
                        "message": "Decryption failed",
                    })

            elif msg.get("type") == MSG_SESSION_CLOSE:
                self.logger.info("Session closed by client")
                print("\n[+] Session closed by client")
                break
            else:
                self.logger.warning("Unexpected message type: %s", msg.get("type"))


def main():
    """
    @brief Entry point for the Server application.

    Creates a Server instance and starts it.
    Catches KeyboardInterrupt for graceful shutdown.
    """
    server = Server()
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nServer shutting down.")
        server.logger.info("Server shut down")


if __name__ == "__main__":
    main()
