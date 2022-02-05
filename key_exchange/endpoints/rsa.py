# -*- coding:utf-8 -*-
import os
from typing import Optional
from nacl.bindings.utils import sodium_memcmp


class RSAEndpoint(object):
    """ Partially implemented RSA_WITH_AES_256_CBC_SHA256
    """
    SESSION_KEY_SIZE = 32
    __session_key: bytes

    def __init__(self, secret: bytes, pubkey: bytes):
        self.__secret = secret
        self.pubkey = pubkey

    def server_hello(self) -> bytes:
        return self.pubkey

    def private_key_decrypt(self, data: bytes) -> bytes:
        return b''

    def receive_session_key(self, data: bytes,
                            handshake: bytes,
                            iv: bytes):
        _key = self.private_key_decrypt(data)

        # TODO:
        #  - Decrypt handshake data with session key.
        #  - Handshake data contains its timestamp with nonce, parse timestamp
        #    to int32.
        #  - Verify handshake timestamp, check whether is timed out.
        #  - Setup session key.

    def encrypt(self, data: bytes,
                iv: Optional[bytes] = None) -> (bytes, bytes):
        if not iv:
            iv = os.urandom(self.SESSION_KEY_SIZE)

        # TODO: Session key encrypt

        return b'', iv

    def decrypt(self, data: bytes,
                iv: bytes) -> bytes:

        # TODO: Session key decrypt

        return b''
