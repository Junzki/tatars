# -*- coding:utf-8 -*-
import unittest
import uuid

import nacl.encoding
import nacl.utils
from nacl.hash import blake2b
from storage.local import JarLoader


class TestPasswordJar(unittest.TestCase):

    def setUp(self) -> None:
        self.secret_key = nacl.utils.random(64)
        self.loader = JarLoader(self.secret_key)

    def test_save(self):
        passwd1 = 'passwd1'
        passwd2 = 'passwd2'

        self.loader.put('user1', passwd1)
        saved = self.loader.get('user1')

        self.assertEqual(passwd1, saved)

        self.loader.put('user1', passwd2)
        saved = self.loader.get('user1')
        self.assertEqual(passwd2, saved)
