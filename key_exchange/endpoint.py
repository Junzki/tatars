# -*- coding:utf-8 -*-
import base64
from typing import Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class Endpoint(object):
    """ AES-256-CBC with Diffie-Hellman exchange endpoint.
    """
    parameters: dh.DHParameters
    __secret_key: dh.DHPrivateKey
    __session_key: Optional[bytes] = None
    __derived: Optional[bytes] = None
    __fernet: Fernet

    def __init__(self, parameters: dh.DHParameters):
        self.parameters = parameters

    def public_key(self) -> dh.DHPublicKey:
        return self.__secret_key.public_key()

    def begin_handshake(self) -> dh.DHPublicKey:
        self.__secret_key = self.parameters.generate_private_key()
        self.__session_key = None
        return self.public_key()

    def handshake(self, peer_pubkey: dh.DHPublicKey,
                  handshake_data: bytes,
                  length: int = 32,  # 256 bits
                  salt: Optional[bytes] = None):
        if not self.__secret_key:
            raise ValueError("not initialized, call `begin_handshake` first")

        self.__session_key = self.__secret_key.exchange(peer_pubkey)

        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=handshake_data
        )

        derived_key = kdf.derive(self.__session_key)
        self.__derived = derived_key

        encoded = base64.urlsafe_b64encode(self.__derived)
        self.__fernet = Fernet(encoded)  # AES-CBC-SHA256 by default.

    def encrypt(self, data: bytes) -> bytes:
        return self.__fernet.encrypt(data)

    def decrypt(self, payload: bytes) -> bytes:
        return self.__fernet.decrypt(payload)
