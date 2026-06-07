"""
@brief Trusted Third Party (TTP) server implementation.

The TTP is the central trust anchor in the system. It:
- Generates its own RSA 4096 key pair and self-signed X.509 certificate
- Accepts registration from Users and Servers
- Issues signed X.509 certificates to registered entities
- Performs mutual authentication between Users and Servers
- Generates and distributes AES-256 session keys

Usage:
    python3 ttp.py
"""

import threading
import logging
import socket
import sys

from common import *


class TTP:
    """
    @brief Trusted Third Party server.

    The TTP listens on a configurable TCP port, accepts registration
    requests from Users and Servers, issues X.509 certificates,
    and orchestrates mutual authentication with session key distribution.
    """

    def __init__(self, host=TTP_HOST, port=TTP_PORT):
        """
        @brief Initialize the TTP server.

        Generates the TTP's RSA 4096 key pair and a self-signed X.509
        certificate. Sets up logging to both file (ttp.log) and console.
        Initializes empty registries for users and servers.

        @param host  IP address to bind to (default: 127.0.0.1).
        @param port  TCP port to listen on (default: 4444).
        """
        self.host = host
        self.port = port
        self.logger = self._setup_logging()

        self.ttp_key = generate_rsa_keypair()
        self.ttp_cert = create_self_signed_cert(self.ttp_key, "TTP")
        self.ttp_cert_pem = serialize_cert(self.ttp_cert)

        ## @brief Registered users, keyed by id_hash.
        self.users = {}
        ## @brief Registered servers, keyed by id_hash.
        self.servers = {}
        ## @brief All registered entities (users + servers), keyed by id_hash.
        self.by_id_hash = {}
        ## @brief Thread lock for concurrent access to registries.
        self.lock = threading.Lock()

        self.logger.info("TTP started — RSA keypair and self-signed cert generated")

    def _setup_logging(self):
        """
        @brief Configure logging with timestamped output to file and console.

        Logs are written to @c ttp.log and also printed to stdout.

        @return  A configured logging.Logger instance.
        """
        logger = logging.getLogger("TTP")
        logger.setLevel(logging.INFO)
        fh = logging.FileHandler("ttp.log")
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
        @brief Start the TTP server's main accept loop.

        Binds to the configured host and port, then accepts incoming
        TCP connections in an infinite loop. Each connection is handled
        in a separate daemon thread.
        """
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((self.host, self.port))
        server_sock.listen(5)
        self.logger.info("Listening on %s:%d", self.host, self.port)
        print(f"TTP listening on {self.host}:{self.port}")

        while True:
            client_sock, addr = server_sock.accept()
            self.logger.info("New connection from %s:%d", *addr)
            t = threading.Thread(
                target=self._handle_client, args=(client_sock, addr), daemon=True
            )
            t.start()

    def _handle_client(self, sock, addr):
        """
        @brief Handle a single client connection from registration onward.

        Protocol sequence:
        1. Send TTP public key to the connecting entity
        2. Receive REGISTER message with encrypted payload (id_hash, public_key, role)
        3. Decrypt and validate the registration
        4. Issue and send an X.509 certificate
        5. Enter command loop for post-registration protocol messages

        @param sock  The client socket.
        @param addr  The client's (host, port) address tuple.
        """
        try:
            # 1. Send TTP public key
            send_msg(sock, {
                "type": MSG_TTP_PUBLIC_KEY,
                "public_key": serialize_public_key(self.ttp_key.public_key()),
            })
            self.logger.info("Sent TTP public key to %s:%d", *addr)

            # 2. Receive REGISTER
            msg = recv_msg(sock)
            if not msg or msg.get("type") != MSG_REGISTER:
                self.logger.warning("Invalid registration from %s:%d", *addr)
                send_msg(sock, {"type": MSG_ERROR, "message": "Expected REGISTER"})
                return

            role = msg.get("role")
            if role not in ("user", "server"):
                send_msg(sock, {"type": MSG_ERROR, "message": "Invalid role"})
                return

            # Decrypt the payload (hybrid: RSA-wrapped AES key + AES ciphertext)
            encrypted_key = bytes.fromhex(msg["encrypted_key"])
            nonce = bytes.fromhex(msg["nonce"])
            ciphertext = bytes.fromhex(msg["ciphertext"])
            try:
                decrypted = hybrid_decrypt(self.ttp_key, encrypted_key, nonce, ciphertext)
            except Exception as e:
                self.logger.error("Decryption failed for %s:%d: %s", *addr, e)
                send_msg(sock, {"type": MSG_ERROR, "message": "Decryption failed"})
                return

            payload = json.loads(decrypted.decode("utf-8"))
            id_hash = payload["id_hash"]
            public_key_pem = payload["public_key"]
            display_id = payload.get("display_id", id_hash[:16])

            public_key = deserialize_public_key(public_key_pem)

            # Issue certificate
            entity_name = f"{role}_{display_id}"
            cert = create_signed_cert(
                public_key, self.ttp_key, self.ttp_cert.subject, entity_name
            )
            cert_pem = serialize_cert(cert)

            entry = {
                "sock": sock,
                "addr": addr,
                "public_key": public_key,
                "public_key_pem": public_key_pem,
                "cert_pem": cert_pem,
                "id_hash": id_hash,
                "display_id": display_id,
            }

            with self.lock:
                self.by_id_hash[id_hash] = entry
                if role == "user":
                    self.users[id_hash] = entry
                else:
                    self.servers[id_hash] = entry

            # Send certificate
            send_msg(sock, {
                "type": MSG_CERTIFICATE,
                "certificate": cert_pem,
                "role": role,
            })
            self.logger.info(
                "Registered %s '%s' (id_hash=%s) — certificate issued",
                role, display_id, id_hash[:16],
            )
            print(f"  [+] {role.title()} '{display_id}' registered")

            # 3. Command loop
            self._command_loop(sock, entry, role)

        except Exception as e:
            self.logger.error("Error handling %s:%d: %s", *addr, e)
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _command_loop(self, sock, entry, role):
        """
        @brief Post-registration message processing loop.

        Waits for protocol messages from the registered entity:
        - AUTH_SERVER: Server initiates authentication
        - AUTH_USER_RESPONSE: User responds to authentication challenge
        - SESSION_CLOSE: Session termination notification

        @param sock   The connection socket.
        @param entry  The entity's registration record dictionary.
        @param role   Either "user" or "server".
        """
        while True:
            msg = recv_msg(sock)
            if msg is None:
                self.logger.info(
                    "Connection closed for %s '%s'",
                    role, entry["display_id"],
                )
                break

            msg_type = msg.get("type")

            if msg_type == MSG_AUTH_SERVER:
                self._handle_auth_server(sock, entry, msg)
            elif msg_type == MSG_AUTH_USER_RESPONSE:
                self._handle_auth_user_response(sock, entry, msg)
            elif msg_type == MSG_SESSION_CLOSE:
                self.logger.info(
                    "Session closed by %s '%s'", role, entry["display_id"]
                )
                print(f"  [i] Session closed by {role} '{entry['display_id']}'")
            else:
                self.logger.warning(
                    "Unknown message type '%s' from %s", msg_type, role
                )

    def _handle_auth_server(self, sock, entry, msg):
        """
        @brief Handle a Server's authentication request.

        Validates the Server's certificate, creates a pending authentication
        record, notifies the Server of successful Server-auth, and sends an
        authentication challenge to the User.

        @param sock   The Server's connection socket.
        @param entry  The Server's registration record.
        @param msg    The AUTH_SERVER message containing user_id_hash.
        """
        server_id_hash = entry["id_hash"]
        user_id_hash = msg.get("user_id_hash")
        if not user_id_hash:
            send_msg(sock, {"type": MSG_ERROR, "message": "Missing user_id_hash"})
            return

        with self.lock:
            user_entry = self.by_id_hash.get(user_id_hash)

        if not user_entry:
            send_msg(sock, {
                "type": MSG_ERROR,
                "message": "User not registered",
            })
            self.logger.warning(
                "Auth failed: user %s not registered", user_id_hash[:16]
            )
            return

        # Validate server cert (basic check)
        try:
            server_cert = deserialize_cert(entry["cert_pem"])
            server_cert.public_key()
        except Exception as e:
            send_msg(sock, {"type": MSG_ERROR, "message": "Invalid server cert"})
            self.logger.error("Server cert validation failed: %s", e)
            return

        self.logger.info(
            "Server '%s' authenticated — proceeding to user auth",
            entry["display_id"],
        )

        # Store pending auth
        with self.lock:
            pending = {
                "server_id_hash": server_id_hash,
                "user_id_hash": user_id_hash,
                "session_key": None,
            }
            self.by_id_hash["_pending_" + user_id_hash] = pending

        # Tell server auth is OK
        send_msg(sock, {
            "type": MSG_AUTH_OK,
            "for": "server",
            "message": "Server authenticated",
        })
        self.logger.info("Sent AUTH_OK to server '%s'", entry["display_id"])
        print(f"  [+] Server '{entry['display_id']}' authenticated by TTP")

        # Tell user to authenticate
        try:
            send_msg(user_entry["sock"], {
                "type": MSG_AUTH_USER_START,
                "server_id_hash": server_id_hash,
            })
            self.logger.info(
                "Sent AUTH_USER_START to user '%s'", user_entry["display_id"]
            )
            print(f"  [i] TTP → User '{user_entry['display_id']}': please authenticate")
        except Exception as e:
            self.logger.error("Failed to notify user: %s", e)

    def _handle_auth_user_response(self, sock, entry, msg):
        """
        @brief Handle a User's authentication response.

        Decrypts the response (hybrid encryption), validates the User's
        identity hash and certificate, generates a session key, and
        distributes it to both User and Server (encrypted with each
        entity's RSA public key).

        @param sock   The User's connection socket.
        @param entry  The User's registration record.
        @param msg    The AUTH_USER_RESPONSE message.
        """
        user_id_hash = entry["id_hash"]

        encrypted_key = bytes.fromhex(msg["encrypted_key"])
        nonce = bytes.fromhex(msg["nonce"])
        ciphertext = bytes.fromhex(msg["ciphertext"])
        try:
            decrypted = hybrid_decrypt(self.ttp_key, encrypted_key, nonce, ciphertext)
        except Exception as e:
            send_msg(sock, {"type": MSG_ERROR, "message": "Decryption failed"})
            self.logger.error("User auth decrypt failed: %s", e)
            return

        payload = json.loads(decrypted.decode("utf-8"))
        response_id_hash = payload["id_hash"]
        cert_pem = payload.get("certificate", "")

        if response_id_hash != user_id_hash:
            send_msg(sock, {"type": MSG_ERROR, "message": "ID mismatch"})
            self.logger.warning(
                "User auth failed: ID mismatch (expected %s, got %s)",
                user_id_hash[:16], response_id_hash[:16],
            )
            return

        # Validate user certificate
        try:
            user_cert = deserialize_cert(cert_pem)
            user_cert.public_key()
        except Exception as e:
            send_msg(sock, {"type": MSG_ERROR, "message": "Invalid cert"})
            self.logger.error("User cert validation failed: %s", e)
            return

        # Find pending auth
        with self.lock:
            pending_key = "_pending_" + user_id_hash
            pending = self.by_id_hash.get(pending_key)
            if pending:
                del self.by_id_hash[pending_key]

        if not pending:
            send_msg(sock, {"type": MSG_ERROR, "message": "No pending auth"})
            self.logger.warning("No pending auth for user %s", user_id_hash[:16])
            return

        # Generate session key (AES-256, using CSPRNG as required)
        session_key = generate_aes_key()
        pending["session_key"] = session_key

        server_entry = self.by_id_hash.get(pending["server_id_hash"])
        if not server_entry:
            send_msg(sock, {"type": MSG_ERROR, "message": "Server gone"})
            return

        self.logger.info(
            "User '%s' authenticated — distributing session key",
            entry["display_id"],
        )
        print(f"  [+] User '{entry['display_id']}' authenticated by TTP")

        # Send session key to user (encrypted with user's RSA public key)
        encrypted_sk_for_user = rsa_encrypt(
            entry["public_key"], session_key
        )
        send_msg(sock, {
            "type": MSG_AUTH_OK,
            "for": "user",
            "session_key_encrypted": encrypted_sk_for_user.hex(),
        })
        self.logger.info("Session key sent to user '%s'", entry["display_id"])
        print(f"  [+] Session key delivered to User '{entry['display_id']}'")

        # Send session key to server (encrypted with server's RSA public key)
        encrypted_sk_for_server = rsa_encrypt(
            server_entry["public_key"], session_key
        )
        try:
            send_msg(server_entry["sock"], {
                "type": MSG_AUTH_OK,
                "for": "server",
                "session_key_encrypted": encrypted_sk_for_server.hex(),
            })
            self.logger.info(
                "Session key sent to server '%s'", server_entry["display_id"]
            )
            print(f"  [+] Session key delivered to Server '{server_entry['display_id']}'")
        except Exception as e:
            self.logger.error("Failed to send session key to server: %s", e)

        # Also tell server the user is authenticated
        try:
            send_msg(server_entry["sock"], {
                "type": MSG_AUTH_OK,
                "for": "server",
                "message": "User authenticated, session key delivered",
            })
        except Exception as e:
            self.logger.error("Failed to notify server of user auth: %s", e)


def main():
    """
    @brief Entry point for the TTP server application.

    Creates a TTP instance and starts the main accept loop.
    Catches KeyboardInterrupt for graceful shutdown.
    """
    ttp = TTP()
    try:
        ttp.start()
    except KeyboardInterrupt:
        print("\nTTP shutting down.")
        ttp.logger.info("TTP shut down")


if __name__ == "__main__":
    main()
