# -*- coding:utf-8 -*-
""" Local file storage with libsodium secret box.
"""
import dataclasses
import json
import uuid
from typing import List, Optional

import nacl.secret
from nacl import pwhash, secret, utils
from .identity import derive_key


JAR_HISTORICAL_SIZE = 5


@dataclasses.dataclass
class Jar:
    identity: str
    current: str = ''
    historical: List[str] = dataclasses.field(default_factory=list)
    encrypted_data: bytes = None

    def push(self, password):
        if self.current:
            self.historical.append(self.current)

        self.current = password

        while len(self.historical) > JAR_HISTORICAL_SIZE:
            self.historical = self.historical[JAR_HISTORICAL_SIZE * -1:]  # Keeps last JAR_HISTORICAL_SIZE items.

        return self

    def serialize(self) -> bytes:
        payload = {
            'identity': self.identity,
            'current': self.current,
            'historical': self.historical
        }
        data_ = json.dumps(payload).encode()
        return data_

    def from_bytes(self, data: bytes):
        data = data.decode()
        payload = json.loads(data)

        for k, v in payload.items():
            setattr(self, k, v)

        return self


class InMemoryAdapter(object):

    def __init__(self):
        self._store = dict()

    def read(self, jar: Jar) -> Optional[Jar]:
        data = self._store.get(jar.identity)
        if not data:
            return None

        jar.encrypted_data = data
        return jar

    def write(self, jar: Jar):
        self._store[jar.identity] = jar.encrypted_data


class JarLoader(object):
    KEY_SIZE = secret.SecretBox.KEY_SIZE

    def __init__(self, secret_key: bytes,
                 storage_adapter: "InMemoryAdapter" = InMemoryAdapter):
        self.__secret = secret_key
        self.store = storage_adapter()

    def put(self, identity: str, password: str):
        jar = Jar(identity)

        existed = self.store.read(jar)

        if existed:
            jar = self._decrypt(existed)
        else:
            jar = Jar(identity=identity)

        jar.push(password)

        jar = self._encrypt(jar)
        self.store.write(jar)

        return self

    def get(self, identity) -> Optional[str]:
        jar = Jar(identity=identity)
        jar = self.store.read(jar)
        if not jar:
            return None

        jar = self._decrypt(jar)
        return jar.current

    def _encrypt(self, jar: Jar) -> Jar:
        key = derive_key(secret=self.__secret, identity=jar.identity)
        data = jar.serialize()

        box = nacl.secret.SecretBox(key)
        encrypted_ = box.encrypt(data)

        jar.encrypted_data = encrypted_

        return jar

    def _decrypt(self, jar: Jar) -> Jar:
        key = derive_key(secret=self.__secret, identity=jar.identity)

        box = nacl.secret.SecretBox(key)
        decrypted_ = box.decrypt(jar.encrypted_data)
        jar = jar.from_bytes(decrypted_)
        return jar
