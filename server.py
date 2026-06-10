"""
Service Server implementation for the BSK project.

Usage:
    python3 server.py
"""

import threading
import logging
import socket
import sys

from common import *


class Server:

    def __init__(self, ttp_host=TTP_HOST, ttp_port=TTP_PORT,
                 server_host=SERVER_HOST, server_port=SERVER_PORT,
                 server_id="Server-01"):
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
        self._register_with_ttp()

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
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.ttp_host, self.ttp_port))
        self.logger.info("Connected to TTP at %s:%d", self.ttp_host, self.ttp_port)
        print(f"Connected to TTP at {self.ttp_host}:{self.ttp_port}")

        msg = recv_msg(sock)
        if not msg or msg.get("type") != MSG_TTP_PUBLIC_KEY:
            self.logger.error("Expected TTP_PUBLIC_KEY from TTP")
            sys.exit(1)

        ttp_public_key_pem = msg["public_key"]
        ttp_public_key = deserialize_public_key(ttp_public_key_pem)
        self.logger.info("Received TTP public key")

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

        msg = recv_msg(sock)
        if not msg or msg.get("type") != MSG_CERTIFICATE:
            self.logger.error("Expected CERTIFICATE from TTP")
            sys.exit(1)

        self.server_cert_pem = msg["certificate"]
        self.logger.info("Received X.509 certificate from TTP")
        print(f"  [+] Server registered with TTP — certificate obtained")
        print(f"  [+] Server ID hash: {id_hash[:16]}...")

        t = threading.Thread(
            target=self._ttp_listener, args=(sock,), daemon=True
        )
        t.start()

    def _ttp_listener(self, sock):
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
        try:
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

                self._initiate_auth(user_id_hash)

                print(f"  [i] Waiting for session key from TTP...")

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
        auth_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        auth_sock.connect((self.ttp_host, self.ttp_port))
        msg = recv_msg(auth_sock)
        if not msg or msg.get("type") != MSG_TTP_PUBLIC_KEY:
            self.logger.error("Expected TTP_PUBLIC_KEY")
            auth_sock.close()
            return
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

        send_msg(auth_sock, {
            "type": MSG_AUTH_SERVER,
            "user_id_hash": user_id_hash,
        })
        self.logger.info("Sent AUTH_SERVER to TTP for user %s", user_id_hash[:16])
        print(f"  [i] Server → TTP: authenticate user {user_id_hash[:16]}...")

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
    server = Server()
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nServer shutting down.")
        server.logger.info("Server shut down")


if __name__ == "__main__":
    main()
