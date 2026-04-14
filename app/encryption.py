"""
Utilitare de criptare/decriptare pentru date sensibile (ex: credențiale MikroTik).

Folosește algoritmul Fernet (AES-128-CBC + HMAC-SHA256) din librăria `cryptography`.
Cheia Fernet este derivată din SECRET_KEY al aplicației folosind SHA-256.
"""
import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken


def _derive_fernet_key(secret_key: str) -> bytes:
    """Derivă o cheie Fernet de 32 de octeți din SECRET_KEY-ul aplicației.

    Folosește SHA-256 pentru a produce exact 32 de octeți, care sunt apoi
    encodați în Base64 URL-safe (formatul așteptat de Fernet).
    """
    digest = hashlib.sha256(secret_key.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(digest)


def encrypt_value(plaintext: str, secret_key: str) -> str:
    """Criptează un text clar și returnează tokenul Fernet ca string.

    :param plaintext: Valoarea de criptat.
    :param secret_key: SECRET_KEY-ul aplicației Flask.
    :returns: Tokenul criptat (string URL-safe).
    :raises ValueError: Dacă plaintext sau secret_key sunt goale.
    """
    if not plaintext:
        raise ValueError('plaintext nu poate fi gol.')
    if not secret_key:
        raise ValueError('secret_key nu poate fi gol.')

    key = _derive_fernet_key(secret_key)
    cipher = Fernet(key)
    return cipher.encrypt(plaintext.encode('utf-8')).decode('utf-8')


def decrypt_value(token: str, secret_key: str) -> str:
    """Decriptează un token Fernet și returnează textul clar.

    :param token: Tokenul criptat (produs de ``encrypt_value``).
    :param secret_key: SECRET_KEY-ul aplicației Flask.
    :returns: Valoarea decriptată ca string.
    :raises ValueError: Dacă token-ul este invalid sau cheia este greșită.
    """
    if not token:
        raise ValueError('token nu poate fi gol.')
    if not secret_key:
        raise ValueError('secret_key nu poate fi gol.')

    key = _derive_fernet_key(secret_key)
    cipher = Fernet(key)
    try:
        return cipher.decrypt(token.encode('utf-8')).decode('utf-8')
    except InvalidToken as exc:
        raise ValueError('Token invalid sau cheie de criptare incorectă.') from exc
