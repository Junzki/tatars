# -*- coding:utf-8 -*-
import mmh3
import nacl.hash
import nacl.encoding
import nacl.utils
import nacl.secret

from typing import Optional


def personalize(identity: str) -> bytes:
    hash_: int = mmh3.hash128(identity)
    return hash_.to_bytes(nacl.hash.BLAKE2B_PERSONALBYTES, 'big', signed=False)


def derive_key(secret: bytes, identity: str, salt: Optional[bytes] = None,
               size: int = nacl.secret.SecretBox.KEY_SIZE) -> bytes:

    key_size = len(secret)
    if not (nacl.hash.BLAKE2B_BYTES_MIN <= key_size <= nacl.hash.BLAKE2B_KEYBYTES_MAX):
        raise ValueError("Secret key should be with in {} and {} bytes.".format(nacl.hash.BLAKE2B_BYTES_MIN,
                                                                                nacl.hash.BLAKE2B_KEYBYTES_MAX))

    if not salt:
        salt = b''

    person = personalize(identity)

    derived = nacl.hash.blake2b(b'', digest_size=size, key=secret, salt=salt, person=person,
                                encoder=nacl.encoding.RawEncoder)

    return derived
