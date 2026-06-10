"""
Client GUI application for the BSK project.

Usage:
    python3 client.py
"""

import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, ttk
import sys

from common import *


class Status:
    DISCONNECTED = "disconnected"
    REGISTERED = "registered"
    AUTHENTICATED = "authenticated"
    SESSION_ACTIVE = "session_active"


class ClientGUI:

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("BSK Client — Secure Communication")
        self.root.geometry("700x600")
        self.root.resizable(True, True)

        self.client_id = "User-01"
        self.client_key = generate_rsa_keypair()
        self.client_cert_pem = None
        self.client_id_hash = None

        self.ttp_sock = None
        self.server_sock = None
        self.session_key = None

        self.status = Status.DISCONNECTED
        self.ttp_public_key = None
        self.auth_in_progress = False

        self._build_ui()
        self._update_status()

    def _build_ui(self):
        conn_frame = ttk.LabelFrame(self.root, text="Connection", padding=5)
        conn_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(conn_frame, text="TTP:").grid(row=0, column=0, sticky="w")
        self.ttp_host_var = tk.StringVar(value=TTP_HOST)
        self.ttp_port_var = tk.StringVar(value=str(TTP_PORT))
        ttk.Entry(conn_frame, textvariable=self.ttp_host_var, width=15).grid(
            row=0, column=1, padx=2
        )
        ttk.Entry(conn_frame, textvariable=self.ttp_port_var, width=6).grid(
            row=0, column=2, padx=2
        )
        self.btn_register = ttk.Button(
            conn_frame, text="Register with TTP", command=self._register
        )
        self.btn_register.grid(row=0, column=3, padx=5)

        ttk.Label(conn_frame, text="Server:").grid(
            row=1, column=0, sticky="w", pady=(5, 0)
        )
        self.srv_host_var = tk.StringVar(value=SERVER_HOST)
        self.srv_port_var = tk.StringVar(value=str(SERVER_PORT))
        ttk.Entry(conn_frame, textvariable=self.srv_host_var, width=15).grid(
            row=1, column=1, padx=2, pady=(5, 0)
        )
        ttk.Entry(conn_frame, textvariable=self.srv_port_var, width=6).grid(
            row=1, column=2, padx=2, pady=(5, 0)
        )
        self.btn_service = ttk.Button(
            conn_frame, text="Request Service", command=self._request_service,
            state="disabled",
        )
        self.btn_service.grid(row=1, column=3, padx=5, pady=(5, 0))

        self.client_id_var = tk.StringVar(value=self.client_id)
        ttk.Label(conn_frame, text="ID:").grid(
            row=2, column=0, sticky="w", pady=(5, 0)
        )
        ttk.Entry(
            conn_frame, textvariable=self.client_id_var, width=20
        ).grid(row=2, column=1, columnspan=2, sticky="w", padx=2, pady=(5, 0))
        ttk.Button(
            conn_frame, text="Disconnect", command=self._disconnect
        ).grid(row=2, column=3, padx=5, pady=(5, 0))

        status_frame = ttk.LabelFrame(self.root, text="Status", padding=5)
        status_frame.pack(fill="x", padx=10, pady=5)

        self.status_canvas = tk.Canvas(status_frame, width=24, height=24,
                                       highlightthickness=0)
        self.status_canvas.grid(row=0, column=0, padx=(0, 10))
        self.status_indicator = self.status_canvas.create_oval(
            4, 4, 24, 24, fill="red", outline="darkgray", width=2
        )

        self.status_label = ttk.Label(
            status_frame, text="Disconnected", font=("", 10, "bold")
        )
        self.status_label.grid(row=0, column=1, sticky="w")

        self.auth_label = ttk.Label(status_frame, text="")
        self.auth_label.grid(row=0, column=2, sticky="w", padx=(20, 0))

        msg_frame = ttk.LabelFrame(self.root, text="Encrypted Messages", padding=5)
        msg_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.msg_display = scrolledtext.ScrolledText(
            msg_frame, height=8, state="disabled", wrap="word"
        )
        self.msg_display.pack(fill="both", expand=True)

        input_row = ttk.Frame(msg_frame)
        input_row.pack(fill="x", pady=(5, 0))

        self.msg_entry = ttk.Entry(input_row)
        self.msg_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        self.msg_entry.bind("<Return>", lambda e: self._send_message())

        self.btn_send = ttk.Button(
            input_row, text="Send", command=self._send_message, state="disabled"
        )
        self.btn_send.pack(side="right")
        self.btn_close = ttk.Button(
            input_row, text="Close Session", command=self._close_session,
            state="disabled",
        )
        self.btn_close.pack(side="right", padx=(0, 5))

        log_frame = ttk.LabelFrame(self.root, text="Event Log", padding=5)
        log_frame.pack(fill="x", padx=10, pady=(0, 10))

        self.log_display = scrolledtext.ScrolledText(
            log_frame, height=6, state="disabled", wrap="word"
        )
        self.log_display.pack(fill="x")

    # --- GUI helpers ---

    def _log(self, message):
        self.log_display.config(state="normal")
        self.log_display.insert("end", message + "\n")
        self.log_display.see("end")
        self.log_display.config(state="disabled")

    def _display_msg(self, direction, text):
        self.msg_display.config(state="normal")
        self.msg_display.insert("end", f"{direction}: {text}\n")
        self.msg_display.see("end")
        self.msg_display.config(state="disabled")

    def _update_status(self, auth_info=None):
        colors = {
            Status.DISCONNECTED: "red",
            Status.REGISTERED: "orange",
            Status.AUTHENTICATED: "green",
            Status.SESSION_ACTIVE: "green",
        }
        self.status_canvas.itemconfig(
            self.status_indicator, fill=colors.get(self.status, "red")
        )
        label_map = {
            Status.DISCONNECTED: "Disconnected",
            Status.REGISTERED: "Registered with TTP",
            Status.AUTHENTICATED: "Authenticated",
            Status.SESSION_ACTIVE: "Session Active",
        }
        self.status_label.config(text=label_map.get(self.status, "Unknown"))
        if auth_info:
            self.auth_label.config(text=auth_info)

    # --- Actions ---

    def _register(self):
        if self.ttp_sock:
            self._log("[!] Already registered with TTP")
            return

        self.client_id = self.client_id_var.get().strip() or "User-01"
        self.client_key = generate_rsa_keypair()
        self.client_id_hash = hash_id(self.client_id)

        def task():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((
                    self.ttp_host_var.get(),
                    int(self.ttp_port_var.get()),
                ))
                self.ttp_sock = sock

                msg = recv_msg(sock)
                if not msg or msg.get("type") != MSG_TTP_PUBLIC_KEY:
                    self.root.after(0, lambda: self._log(
                        "[!] Expected TTP_PUBLIC_KEY"
                    ))
                    sock.close()
                    self.ttp_sock = None
                    return

                self.ttp_public_key = deserialize_public_key(msg["public_key"])
                self.root.after(0, lambda: self._log(
                    "[+] Received TTP public key"
                ))

                id_hash = hash_id(self.client_id)
                self.client_id_hash = id_hash
                pub_pem = serialize_public_key(self.client_key.public_key())
                payload = json.dumps({
                    "id_hash": id_hash,
                    "public_key": pub_pem,
                    "display_id": self.client_id,
                }).encode("utf-8")
                ekey, nonce, ct = hybrid_encrypt(self.ttp_public_key, payload)

                send_msg(sock, {
                    "type": MSG_REGISTER,
                    "role": "user",
                    "encrypted_key": ekey.hex(),
                    "nonce": nonce.hex(),
                    "ciphertext": ct.hex(),
                })

                msg = recv_msg(sock)
                if not msg or msg.get("type") != MSG_CERTIFICATE:
                    self.root.after(0, lambda: self._log(
                        "[!] Expected CERTIFICATE"
                    ))
                    sock.close()
                    self.ttp_sock = None
                    return

                self.client_cert_pem = msg["certificate"]
                self.status = Status.REGISTERED
                self.root.after(0, self._on_registered)

            except Exception as e:
                self.root.after(0, lambda: self._log(
                    f"[!] Registration failed: {e}"
                ))

        threading.Thread(target=task, daemon=True).start()

    def _on_registered(self):
        self._log(f"[+] Registered with TTP as '{self.client_id}'")
        self._log(f"[+] ID hash: {self.client_id_hash[:16]}...")
        self._log(f"[+] X.509 certificate obtained from TTP")
        self._update_status("TTP: registered")
        self.btn_register.config(state="disabled")
        self.btn_service.config(state="normal")
        self._start_ttp_listener()

    def _start_ttp_listener(self):
        def listener():
            sock = self.ttp_sock
            try:
                while sock:
                    msg = recv_msg(sock)
                    if msg is None:
                        break
                    self.root.after(0, self._handle_ttp_message, msg)
            except Exception:
                pass
            finally:
                self.root.after(0, self._on_ttp_disconnect)

        threading.Thread(target=listener, daemon=True).start()

    def _handle_ttp_message(self, msg):
        msg_type = msg.get("type")
        if msg_type == MSG_AUTH_USER_START:
            self._log("[TTP] Server authenticated, please authenticate yourself")
            self._log("[TTP] Sending authentication response...")
            self._respond_auth()
        elif msg_type == MSG_AUTH_OK:
            for_field = msg.get("for")
            if for_field == "user":
                sk_enc_hex = msg.get("session_key_encrypted")
                if sk_enc_hex:
                    encrypted_sk = bytes.fromhex(sk_enc_hex)
                    self.session_key = rsa_decrypt(
                        self.client_key, encrypted_sk
                    )
                    self.status = Status.AUTHENTICATED
                    self._update_status("Session key received")
                    self._log("[+] Session key received from TTP!")
                    self._log("[+] Mutual authentication complete!")
                    self._on_authenticated()
            else:
                if msg.get("message"):
                    self._log(f"[TTP] {msg['message']}")
        elif msg_type == MSG_ERROR:
            self._log(f"[!] TTP error: {msg.get('message')}")

    def _respond_auth(self):
        def task():
            try:
                payload = json.dumps({
                    "id_hash": self.client_id_hash,
                    "certificate": self.client_cert_pem,
                }).encode("utf-8")
                ekey, nonce, ct = hybrid_encrypt(
                    self.ttp_public_key, payload
                )
                send_msg(self.ttp_sock, {
                    "type": MSG_AUTH_USER_RESPONSE,
                    "encrypted_key": ekey.hex(),
                    "nonce": nonce.hex(),
                    "ciphertext": ct.hex(),
                })
                self._log("[+] Authentication response sent to TTP")
            except Exception as e:
                self._log(f"[!] Auth response failed: {e}")

        threading.Thread(target=task, daemon=True).start()

    def _on_authenticated(self):
        self.btn_service.config(state="disabled")
        self.btn_send.config(state="normal")
        self.btn_close.config(state="normal")

    def _request_service(self):
        if self.server_sock:
            self._log("[!] Already connected to server")
            return

        def task():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((
                    self.srv_host_var.get(),
                    int(self.srv_port_var.get()),
                ))
                self.server_sock = sock

                send_msg(sock, {
                    "type": MSG_SERVICE_REQUEST,
                    "user_id_hash": self.client_id_hash,
                    "service_type": "encrypted_echo",
                })
                self._log("[+] Service request sent to server")
                self._log("[i] Waiting for authentication via TTP...")

                self._start_server_listener()

            except Exception as e:
                self._log(f"[!] Service request failed: {e}")

        threading.Thread(target=task, daemon=True).start()

    def _start_server_listener(self):
        def listener():
            sock = self.server_sock
            try:
                while sock:
                    msg = recv_msg(sock)
                    if msg is None:
                        break
                    self.root.after(0, self._handle_server_message, msg)
            except Exception:
                pass
            finally:
                self.root.after(0, self._on_server_disconnect)

        threading.Thread(target=listener, daemon=True).start()

    def _handle_server_message(self, msg):
        msg_type = msg.get("type")
        if msg_type == MSG_ENCRYPTED_DATA:
            nonce = bytes.fromhex(msg["nonce"])
            ciphertext = bytes.fromhex(msg["ciphertext"])
            try:
                plaintext = aes_decrypt(self.session_key, nonce, ciphertext)
                decoded = plaintext.decode("utf-8")
                self._display_msg("RECEIVED (encrypted)", decoded)
            except Exception as e:
                self._display_msg("ERROR", f"Decryption failed: {e}")
        elif msg_type == MSG_AUTH_OK:
            self._log(f"[Server] {msg.get('message', 'OK')}")
        elif msg_type == MSG_ERROR:
            self._log(f"[!] Server error: {msg.get('message')}")
        elif msg_type == MSG_SESSION_CLOSE:
            self._log("[Server] Session closed by server")
            self._reset_session()

    def _send_message(self):
        text = self.msg_entry.get().strip()
        if not text or not self.session_key or not self.server_sock:
            return
        self.msg_entry.delete(0, "end")

        def task():
            try:
                nonce, ciphertext = aes_encrypt(
                    self.session_key, text.encode("utf-8")
                )
                send_msg(self.server_sock, {
                    "type": MSG_ENCRYPTED_DATA,
                    "nonce": nonce.hex(),
                    "ciphertext": ciphertext.hex(),
                })
                self.root.after(0, lambda: self._display_msg(
                    "SENT (encrypted)", text
                ))
            except Exception as e:
                self.root.after(0, lambda: self._log(
                    f"[!] Send failed: {e}"
                ))

        threading.Thread(target=task, daemon=True).start()

    def _close_session(self):
        if self.server_sock:
            try:
                send_msg(self.server_sock, {"type": MSG_SESSION_CLOSE})
            except Exception:
                pass
        if self.ttp_sock:
            try:
                send_msg(self.ttp_sock, {"type": MSG_SESSION_CLOSE})
            except Exception:
                pass
        self._log("[+] Session closed")
        self._reset_session()

    def _reset_session(self):
        self.session_key = None
        self.status = Status.REGISTERED
        self._update_status("Session closed")
        self.btn_send.config(state="disabled")
        self.btn_close.config(state="disabled")
        self.btn_service.config(state="normal")

    def _on_server_disconnect(self):
        self.server_sock = None
        self._log("[!] Server disconnected")
        self._reset_session()

    def _on_ttp_disconnect(self):
        self.ttp_sock = None
        self._log("[!] TTP disconnected")
        self.status = Status.DISCONNECTED
        self._update_status()
        self.btn_register.config(state="normal")
        self.btn_service.config(state="disabled")
        self.btn_send.config(state="disabled")
        self.btn_close.config(state="disabled")

    def _disconnect(self):
        self._close_session()
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass
            self.server_sock = None
        if self.ttp_sock:
            try:
                self.ttp_sock.close()
            except Exception:
                pass
            self.ttp_sock = None
        self.status = Status.DISCONNECTED
        self._update_status()
        self.btn_register.config(state="normal")
        self.btn_service.config(state="disabled")
        self.btn_send.config(state="disabled")
        self.btn_close.config(state="disabled")
        self._log("[-] Disconnected")

    def run(self):
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.mainloop()

    def _on_close(self):
        self._disconnect()
        self.root.destroy()


def main():
    app = ClientGUI()
    app.run()


if __name__ == "__main__":
    main()
