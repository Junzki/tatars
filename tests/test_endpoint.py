# -*- coding:utf-8 -*-
import os
import unittest
from cryptography.hazmat.primitives.asymmetric import dh
from key_exchange.endpoint import Endpoint


class TestEndpoint(unittest.TestCase):

    class PatchedEndpoint(Endpoint):

        def __eq__(self, other):
            return self._Endpoint__derived == other._Endpoint__derived  # Get private field

    def setUp(self) -> None:
        params = dh.generate_parameters(generator=2, key_size=2048)

        p1 = self.PatchedEndpoint(params)
        p2 = self.PatchedEndpoint(params)

        pub1 = p1.begin_handshake()
        pub2 = p2.begin_handshake()

        handshake = b'handshake'
        p1.handshake(pub2, handshake)
        p2.handshake(pub1, handshake)

        self.p1 = p1
        self.p2 = p2

    def test_peering(self):
        self.assertEqual(self.p1, self.p2)

    def test_encrypt_decrypt(self):
        data = os.urandom(2048)
        encrypted = self.p1.encrypt(data)
        decrypted = self.p2.decrypt(encrypted)

        self.assertEqual(data, decrypted)
