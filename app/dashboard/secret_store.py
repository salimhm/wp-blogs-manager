"""Small encrypted-at-rest store for provisioning-only credentials."""

import base64
import hashlib
import os

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings


def _fernet():
    configured_key = os.environ.get('PROVISIONING_ENCRYPTION_KEY', '').strip()
    if configured_key:
        key = configured_key.encode('ascii')
    else:
        digest = hashlib.sha256(settings.SECRET_KEY.encode('utf-8')).digest()
        key = base64.urlsafe_b64encode(digest)
    return Fernet(key)


def encrypt_secret(value):
    if value is None:
        return ''
    return _fernet().encrypt(str(value).encode('utf-8')).decode('ascii')


def decrypt_secret(value):
    if not value:
        return ''
    try:
        return _fernet().decrypt(value.encode('ascii')).decode('utf-8')
    except InvalidToken as exc:
        raise ValueError(
            'Provisioning secret cannot be decrypted. Check PROVISIONING_ENCRYPTION_KEY.'
        ) from exc

