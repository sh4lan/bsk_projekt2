"""
Shared cryptographic utilities and protocol definitions for the BSK project.
"""

import json
import os
import socket
import struct
import datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID

# --- Protocol constants ---

TTP_HOST = "127.0.0.1"
TTP_PORT = 4444

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5555

RSA_KEY_SIZE = 4096
AES_KEY_SIZE = 32

# Message types used in the protocol between TTP, Server, and Client.

MSG_TTP_PUBLIC_KEY = "TTP_PUBLIC_KEY"
MSG_REGISTER = "REGISTER"
MSG_CERTIFICATE = "CERTIFICATE"
MSG_SERVICE_REQUEST = "SERVICE_REQUEST"
MSG_AUTH_SERVER = "AUTH_SERVER"
MSG_AUTH_USER_START = "AUTH_USER_START"
MSG_AUTH_USER_RESPONSE = "AUTH_USER_RESPONSE"
MSG_AUTH_OK = "AUTH_OK"
MSG_ENCRYPTED_DATA = "ENCRYPTED_DATA"
MSG_SESSION_CLOSE = "SESSION_CLOSE"
MSG_ERROR = "ERROR"


# --- TCP helpers ---


def send_msg(sock, msg_dict):
    data = json.dumps(msg_dict).encode("utf-8")
    sock.sendall(struct.pack("!I", len(data)))
    sock.sendall(data)


def recv_msg(sock):
    raw_len = _recv_exact(sock, 4)
    if not raw_len:
        return None
    msg_len = struct.unpack("!I", raw_len)[0]
    data = _recv_exact(sock, msg_len)
    if not data:
        return None
    return json.loads(data.decode("utf-8"))


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


# --- RSA helpers ---


def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
    )
    return private_key


def rsa_encrypt(public_key, data):
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(private_key, ciphertext):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def deserialize_public_key(pem_str):
    return serialization.load_pem_public_key(pem_str.encode("utf-8"))


def serialize_private_key(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def deserialize_private_key(pem_str):
    return serialization.load_pem_private_key(
        pem_str.encode("utf-8"), password=None
    )


# --- Hybrid encryption (RSA wraps AES key for large payloads) ---


def hybrid_encrypt(public_key, plaintext):
    session_key = generate_aes_key()
    aesgcm = AESGCM(session_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    encrypted_key = rsa_encrypt(public_key, session_key)
    return encrypted_key, nonce, ciphertext


def hybrid_decrypt(private_key, encrypted_key, nonce, ciphertext):
    session_key = rsa_decrypt(private_key, encrypted_key)
    aesgcm = AESGCM(session_key)
    return aesgcm.decrypt(nonce, ciphertext, None)


# --- AES helpers ---


def generate_aes_key():
    return os.urandom(AES_KEY_SIZE)


def aes_encrypt(key, plaintext):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext


def aes_decrypt(key, nonce, ciphertext):
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


# --- SHA-256 helpers ---


def hash_id(data):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data.encode("utf-8"))
    return digest.finalize().hex()


# --- X.509 certificate helpers ---


def create_self_signed_cert(private_key, common_name="TTP"):
    public_key = private_key.public_key()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .sign(private_key, hashes.SHA256())
    )
    return cert


def create_signed_cert(csr_public_key, issuer_private_key, issuer_cert_subject,
                       common_name="Client"):
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert_subject)
        .public_key(csr_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .sign(issuer_private_key, hashes.SHA256())
    )
    return cert


def serialize_cert(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def deserialize_cert(pem_str):
    return x509.load_pem_x509_certificate(pem_str.encode("utf-8"))


def cert_to_public_key(cert):
    return cert.public_key()


def verify_cert_signature(cert, ca_cert):
    ca_public_key = ca_cert.public_key()
    ca_public_key.verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
    )
