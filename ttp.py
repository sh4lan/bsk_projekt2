"""
Trusted Third Party (TTP) server implementation.

Usage:
    python3 ttp.py
"""

import threading
import logging
import socket
import sys

from common import *


class TTP:

    def __init__(self, host=TTP_HOST, port=TTP_PORT):
        self.host = host
        self.port = port
        self.logger = self._setup_logging()

        self.ttp_key = generate_rsa_keypair()
        self.ttp_cert = create_self_signed_cert(self.ttp_key, "TTP")
        self.ttp_cert_pem = serialize_cert(self.ttp_cert)

        self.users = {}
        self.servers = {}
        self.by_id_hash = {}
        self.lock = threading.Lock()

        self.logger.info("TTP started — RSA keypair and self-signed cert generated")

    def _setup_logging(self):
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
        try:
            send_msg(sock, {
                "type": MSG_TTP_PUBLIC_KEY,
                "public_key": serialize_public_key(self.ttp_key.public_key()),
            })
            self.logger.info("Sent TTP public key to %s:%d", *addr)

            msg = recv_msg(sock)
            if not msg or msg.get("type") != MSG_REGISTER:
                self.logger.warning("Invalid registration from %s:%d", *addr)
                send_msg(sock, {"type": MSG_ERROR, "message": "Expected REGISTER"})
                return

            role = msg.get("role")
            if role not in ("user", "server"):
                send_msg(sock, {"type": MSG_ERROR, "message": "Invalid role"})
                return

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

            self._command_loop(sock, entry, role)

        except Exception as e:
            self.logger.error("Error handling %s:%d: %s", *addr, e)
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _command_loop(self, sock, entry, role):
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

        try:
            server_cert = deserialize_cert(entry["cert_pem"])
            verify_cert_signature(server_cert, self.ttp_cert)
        except Exception as e:
            send_msg(sock, {"type": MSG_ERROR, "message": "Invalid server cert"})
            self.logger.error("Server cert validation failed: %s", e)
            return

        self.logger.info(
            "Server '%s' authenticated — proceeding to user auth",
            entry["display_id"],
        )

        with self.lock:
            pending = {
                "server_id_hash": server_id_hash,
                "user_id_hash": user_id_hash,
                "session_key": None,
            }
            self.by_id_hash["_pending_" + user_id_hash] = pending

        send_msg(sock, {
            "type": MSG_AUTH_OK,
            "for": "server",
            "message": "Server authenticated",
        })
        self.logger.info("Sent AUTH_OK to server '%s'", entry["display_id"])
        print(f"  [+] Server '{entry['display_id']}' authenticated by TTP")

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

        try:
            user_cert = deserialize_cert(cert_pem)
            verify_cert_signature(user_cert, self.ttp_cert)
        except Exception as e:
            send_msg(sock, {"type": MSG_ERROR, "message": "Invalid cert — not signed by TTP"})
            self.logger.error("User cert validation failed: %s", e)
            return

        with self.lock:
            pending_key = "_pending_" + user_id_hash
            pending = self.by_id_hash.get(pending_key)
            if pending:
                del self.by_id_hash[pending_key]

        if not pending:
            send_msg(sock, {"type": MSG_ERROR, "message": "No pending auth"})
            self.logger.warning("No pending auth for user %s", user_id_hash[:16])
            return

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

        try:
            send_msg(server_entry["sock"], {
                "type": MSG_AUTH_OK,
                "for": "server",
                "message": "User authenticated, session key delivered",
            })
        except Exception as e:
            self.logger.error("Failed to notify server of user auth: %s", e)


def main():
    ttp = TTP()
    try:
        ttp.start()
    except KeyboardInterrupt:
        print("\nTTP shutting down.")
        ttp.logger.info("TTP shut down")


if __name__ == "__main__":
    main()
