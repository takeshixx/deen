import sys
import os
import unittest
import tempfile
import hashlib
import random
import string

from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt
from PyQt5.QtTest import QTest

from deen.widgets.core import Deen

app = QApplication(sys.argv)


class TestGui(unittest.TestCase):
    def setUp(self):
        self.deen = Deen()
        # The list of sub-widgets
        self.widgets = self.deen.encoder_widget.widgets

    def _random_str(self, length=16):
        return ''.join(random.choice(string.ascii_uppercase + string.digits)
                       for _ in range(length))

    def _random_bytes(self, length=16):
        return os.urandom(length)

    def test_quit_app(self):
        self.deen.quit.trigger()

    def test_load_frome_file(self):
        test_file = '/bin/id'
        hasher = hashlib.new('sha256')
        with open(test_file, 'rb') as temp_file:
            hasher.update(temp_file.read())
        test_file_hash = hasher.digest()
        self.deen.load_from_file(file_name=test_file)
        hasher = hashlib.new('sha256')
        hasher.update(self.widgets[0].content)
        self.assertEqual(test_file_hash, hasher.digest())

    def test_save_to_file(self):
        data_str = self._random_str(1024)
        hasher = hashlib.new('sha256')
        hasher.update(data_str.encode())
        data_str_hash = hasher.digest()
        self.widgets[0].text_field.setPlainText(data_str)
        file_name = self._random_str(32)
        with tempfile.TemporaryDirectory() as tmpdirname:
            temp_file = tmpdirname + '/' + file_name
            self.widgets[0].save_content(file_name=temp_file)
            hasher = hashlib.new('sha256')
            with open(temp_file, 'rb') as temp_file:
                hasher.update(temp_file.read())
                temp_file_hash = hasher.digest()
        self.assertEqual(data_str_hash, temp_file_hash)

    def test_save_to_file_binary(self):
        test_file = '/bin/id'
        hasher = hashlib.new('sha256')
        with open(test_file, 'rb') as temp_file:
            hasher.update(temp_file.read())
        input_file_hash = hasher.digest()
        self.deen.load_from_file(file_name=test_file)
        file_name = self._random_str(32)
        with tempfile.TemporaryDirectory() as tmpdirname:
            temp_file = tmpdirname + '/' + file_name
            self.widgets[0].save_content(file_name=temp_file)
            hasher = hashlib.new('sha256')
            with open(temp_file, 'rb') as temp_file:
                hasher.update(temp_file.read())
                temp_file_hash = hasher.digest()
        self.assertEqual(input_file_hash, temp_file_hash)


if __name__ == '__main__':
    unittest.main()