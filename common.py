"""
@brief Shared cryptographic utilities and protocol definitions for the BSK project.

This module provides all common functionality used across the TTP, Server,
and Client applications:
- TCP communication helpers (length-prefixed JSON messaging)
- RSA 4096 key generation, encryption, and decryption
- AES 256-bit GCM authenticated encryption
- Hybrid encryption (RSA-wrapped AES key for large payloads)
- SHA-256 hashing for entity identifiers
- X.509 certificate generation and serialization
- Protocol message type constants
"""

import json
import os
import socket
import struct
import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID

# --- Protocol constants ---

## @brief Default TTP server host address.
TTP_HOST = "127.0.0.1"
## @brief Default TTP server TCP port.
TTP_PORT = 4444

## @brief Default service server host address.
SERVER_HOST = "127.0.0.1"
## @brief Default service server TCP port.
SERVER_PORT = 5555

## @brief RSA key size in bits (4096 as required by the specification).
RSA_KEY_SIZE = 4096
## @brief AES key size in bytes (32 bytes = 256 bits as required by the specification).
AES_KEY_SIZE = 32

# Message types used in the protocol between TTP, Server, and Client.

## @brief TTP sends its RSA public key to connecting entities.
MSG_TTP_PUBLIC_KEY = "TTP_PUBLIC_KEY"
## @brief Entity registration request (encrypted with TTP's public key).
MSG_REGISTER = "REGISTER"
## @brief TTP sends an X.509 certificate to a registered entity.
MSG_CERTIFICATE = "CERTIFICATE"
## @brief Client requests a service from the Server.
MSG_SERVICE_REQUEST = "SERVICE_REQUEST"
## @brief Server requests authentication of itself and a user from TTP.
MSG_AUTH_SERVER = "AUTH_SERVER"
## @brief TTP asks the User to begin authentication.
MSG_AUTH_USER_START = "AUTH_USER_START"
## @brief User responds to TTP's authentication challenge.
MSG_AUTH_USER_RESPONSE = "AUTH_USER_RESPONSE"
## @brief Authentication succeeded; contains session key if applicable.
MSG_AUTH_OK = "AUTH_OK"
## @brief Encrypted payload between User and Server using session key.
MSG_ENCRYPTED_DATA = "ENCRYPTED_DATA"
## @brief Close an active session.
MSG_SESSION_CLOSE = "SESSION_CLOSE"
## @brief Error response.
MSG_ERROR = "ERROR"


# --- TCP helpers ---

def send_msg(sock, msg_dict):
    """
    @brief Send a JSON-encoded dictionary over a TCP socket with length prefix.

    Encodes the dictionary as UTF-8 JSON, then sends a 4-byte big-endian
    unsigned integer length prefix followed by the payload.

    @param sock  An open TCP socket.
    @param msg_dict  Dictionary to serialize and send (must be JSON-serializable).
    """
    data = json.dumps(msg_dict).encode("utf-8")
    sock.sendall(struct.pack("!I", len(data)))
    sock.sendall(data)


def recv_msg(sock):
    """
    @brief Receive a JSON-encoded message from a TCP socket.

    Reads 4 bytes for the length prefix, then reads exactly that many bytes
    and deserializes the JSON payload.

    @param sock  An open TCP socket.
    @return      Deserialized dictionary, or @c None if the connection was closed.
    """
    raw_len = _recv_exact(sock, 4)
    if not raw_len:
        return None
    msg_len = struct.unpack("!I", raw_len)[0]
    data = _recv_exact(sock, msg_len)
    if not data:
        return None
    return json.loads(data.decode("utf-8"))


def _recv_exact(sock, n):
    """
    @brief Read exactly @p n bytes from a socket.

    Handles partial reads by looping until all requested bytes are received.

    @param sock  An open TCP socket.
    @param n     Number of bytes to read.
    @return      Byte string of length @p n, or @c None if connection closed.
    """
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


# --- RSA helpers ---

def generate_rsa_keypair():
    """
    @brief Generate a new RSA 4096-bit key pair.

    Uses a public exponent of 65537. The result is a private key object;
    the public key is obtained via @c .public_key().

    @return  A private RSA key (cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey).
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
    )
    return private_key


def rsa_encrypt(public_key, data):
    """
    @brief Encrypt data using RSA-OAEP with SHA-256.

    @param public_key  Recipient's RSA public key.
    @param data        Plaintext bytes to encrypt (max ~446 bytes for RSA-4096 OAEP).
    @return            Encrypted ciphertext bytes.
    """
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(private_key, ciphertext):
    """
    @brief Decrypt RSA-OAEP ciphertext using a private key.

    @param private_key  The recipient's RSA private key.
    @param ciphertext   Encrypted bytes to decrypt.
    @return             Decrypted plaintext bytes.
    """
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def serialize_public_key(public_key):
    """
    @brief Serialize an RSA public key to PEM format string.

    @param public_key  An RSA public key object.
    @return            PEM-encoded string (including header/footer).
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def deserialize_public_key(pem_str):
    """
    @brief Load an RSA public key from a PEM format string.

    @param pem_str  PEM-encoded public key string.
    @return         A public key object.
    """
    return serialization.load_pem_public_key(pem_str.encode("utf-8"))


def serialize_private_key(private_key):
    """
    @brief Serialize a private key to PEM PKCS#8 format (unencrypted).

    @param private_key  An RSA private key object.
    @return             PEM-encoded string.
    """
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def deserialize_private_key(pem_str):
    """
    @brief Load a private key from PEM PKCS#8 format.

    @param pem_str  PEM-encoded private key string.
    @return         A private key object.
    """
    return serialization.load_pem_private_key(
        pem_str.encode("utf-8"), password=None
    )


# --- Hybrid encryption (RSA wraps AES key for large payloads) ---

def hybrid_encrypt(public_key, plaintext):
    """
    @brief Encrypt arbitrary-length data using hybrid RSA-AES.

    RSA-4096 OAEP can only encrypt ~446 bytes directly. This function
    generates a random AES-256 key, encrypts the plaintext with AES-GCM,
    then wraps the AES key with RSA-OAEP using the recipient's public key.

    @param public_key  Recipient's RSA public key.
    @param plaintext   Plaintext bytes of any length.
    @return            Tuple of (encrypted_aes_key, nonce, ciphertext).
                       - encrypted_aes_key: RSA-OAEP-encrypted AES key (bytes)
                       - nonce: 12-byte AES-GCM nonce (bytes)
                       - ciphertext: AES-GCM ciphertext including authentication tag (bytes)
    """
    session_key = generate_aes_key()
    aesgcm = AESGCM(session_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    encrypted_key = rsa_encrypt(public_key, session_key)
    return encrypted_key, nonce, ciphertext


def hybrid_decrypt(private_key, encrypted_key, nonce, ciphertext):
    """
    @brief Decrypt data encrypted with hybrid_encrypt.

    Recovers the AES-256 key via RSA-OAEP decryption, then decrypts the
    AES-GCM ciphertext.

    @param private_key    Recipient's RSA private key.
    @param encrypted_key  RSA-OAEP-encrypted AES key (bytes).
    @param nonce          12-byte AES-GCM nonce (bytes).
    @param ciphertext     AES-GCM ciphertext with authentication tag (bytes).
    @return               Decrypted plaintext bytes.
    """
    session_key = rsa_decrypt(private_key, encrypted_key)
    aesgcm = AESGCM(session_key)
    return aesgcm.decrypt(nonce, ciphertext, None)


# --- AES helpers ---

def generate_aes_key():
    """
    @brief Generate a cryptographically secure random AES-256 key.

    Uses os.urandom (CSPRNG) as required by the specification.

    @return  32 bytes (256 bits) for use as an AES-256 key.
    """
    return os.urandom(AES_KEY_SIZE)


def aes_encrypt(key, plaintext):
    """
    @brief Encrypt data using AES-256-GCM.

    AES-GCM provides both confidentiality and authentication (integrity
    verification). A random 12-byte nonce is generated for each encryption.

    @param key        32-byte AES-256 key.
    @param plaintext  Plaintext bytes to encrypt.
    @return           Tuple of (nonce, ciphertext_with_tag).
                      - nonce: 12-byte nonce (bytes)
                      - ciphertext: includes the GCM authentication tag (bytes)
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext


def aes_decrypt(key, nonce, ciphertext):
    """
    @brief Decrypt AES-256-GCM ciphertext.

    Raises an exception if the authentication tag verification fails.

    @param key        32-byte AES-256 key.
    @param nonce      12-byte nonce (bytes).
    @param ciphertext AES-GCM ciphertext with authentication tag (bytes).
    @return           Decrypted plaintext bytes.
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


# --- SHA-256 helpers ---

def hash_id(data):
    """
    @brief Compute a SHA-256 hash of a string identifier.

    Used to generate entity ID hashes for registration, as required by
    the specification (public User and Server IDs must be generated
    using a secure hash algorithm).

    @param data  Input string (e.g., entity name).
    @return      Hexadecimal digest string (64 hex characters).
    """
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data.encode("utf-8"))
    return digest.finalize().hex()


# --- X.509 certificate helpers ---

def create_self_signed_cert(private_key, common_name="TTP"):
    """
    @brief Create a self-signed X.509 certificate.

    The TTP uses this to bootstrap its own certificate authority identity.
    The certificate is valid for 365 days and includes the BasicConstraints
    CA extension marking it as a Certificate Authority.

    @param private_key  The TTP's RSA private key used for signing.
    @param common_name  The Common Name (CN) for the certificate subject/issuer.
    @return             An x509.Certificate object.
    """
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
    """
    @brief Issue a signed X.509 certificate for an entity.

    The TTP uses this to issue certificates to registered Users and Servers.
    The certificate is signed by the TTP's private key and does not have
    CA capabilities (BasicConstraints CA=false).

    @param csr_public_key       The entity's RSA public key to certify.
    @param issuer_private_key   The TTP's RSA private key for signing.
    @param issuer_cert_subject  The Name object from the TTP's certificate (used as issuer).
    @param common_name          The Common Name (CN) for the new certificate.
    @return                     An x509.Certificate object.
    """
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
    """
    @brief Serialize an X.509 certificate to PEM format string.

    @param cert  An x509.Certificate object.
    @return      PEM-encoded certificate string.
    """
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def deserialize_cert(pem_str):
    """
    @brief Load an X.509 certificate from a PEM format string.

    @param pem_str  PEM-encoded certificate string.
    @return         An x509.Certificate object.
    """
    return x509.load_pem_x509_certificate(pem_str.encode("utf-8"))


def cert_to_public_key(cert):
    """
    @brief Extract the public key from an X.509 certificate.

    @param cert  An x509.Certificate object.
    @return      The public key object contained in the certificate.
    """
    return cert.public_key()
